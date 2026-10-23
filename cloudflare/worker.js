// Servidor de Finanzas Taxi en Cloudflare Workers.
// Responde las mismas rutas que la versión de Netlify para que la interfaz funcione
// sin cambios: el acceso con cuenta en /.netlify/identity (compatible con lo que
// espera src/auth.js) y los datos en /api/*, guardados en la base de datos D1.

/* ---------- Esquema de la base de datos ---------- */

const AHORA = "(strftime('%Y-%m-%dT%H:%M:%fZ','now'))";
const ESQUEMA = [
  `CREATE TABLE IF NOT EXISTS usuarios (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    user_metadata TEXT NOT NULL DEFAULT '{}',
    creado_at TEXT NOT NULL DEFAULT ${AHORA},
    actualizado_at TEXT NOT NULL DEFAULT ${AHORA}
  )`,
  // Llaves de renovación de las sesiones abiertas (se guarda solo su hash).
  `CREATE TABLE IF NOT EXISTS sesiones (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    creada_at TEXT NOT NULL DEFAULT ${AHORA},
    usada_at TEXT NOT NULL DEFAULT ${AHORA}
  )`,
  `CREATE INDEX IF NOT EXISTS sesiones_user_idx ON sesiones (user_id)`,
  // Código de recuperación de cada cuenta (se guarda solo su hash). Sirve para poner una
  // contraseña nueva sin correo.
  `CREATE TABLE IF NOT EXISTS recuperacion (
    user_id TEXT PRIMARY KEY,
    codigo_hash TEXT NOT NULL,
    creado_at TEXT NOT NULL DEFAULT ${AHORA}
  )`,
  `CREATE TABLE IF NOT EXISTS ajustes (clave TEXT PRIMARY KEY, valor TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS jornadas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    abierta_at TEXT NOT NULL DEFAULT ${AHORA},
    cerrada_at TEXT,
    te_tengo_manual REAL,
    me_tienes_manual REAL,
    fecha TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS jornadas_user_cerrada_idx ON jornadas (user_id, cerrada_at)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS jornadas_una_abierta_idx ON jornadas (user_id) WHERE cerrada_at IS NULL`,
  `CREATE TABLE IF NOT EXISTS movimientos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    jornada_id INTEGER REFERENCES jornadas (id),
    tipo TEXT NOT NULL,
    monto REAL NOT NULL,
    fecha TEXT NOT NULL,
    nota TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ${AHORA}
  )`,
  `CREATE INDEX IF NOT EXISTS movimientos_user_fecha_idx ON movimientos (user_id, fecha)`,
  `CREATE INDEX IF NOT EXISTS movimientos_jornada_idx ON movimientos (jornada_id)`,
  `CREATE TABLE IF NOT EXISTS pagos_socio (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    tipo TEXT NOT NULL DEFAULT 'me_tienes',
    monto REAL NOT NULL,
    nota TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ${AHORA}
  )`,
  `CREATE INDEX IF NOT EXISTS pagos_socio_user_idx ON pagos_socio (user_id)`,
];

// Las tablas se crean solas la primera vez, así no hace falta ningún paso manual.
let esquemaListo = null;
function prepararEsquema(env) {
  if (!esquemaListo) {
    esquemaListo = env.DB.batch(ESQUEMA.map((s) => env.DB.prepare(s))).catch((err) => {
      esquemaListo = null;
      throw err;
    });
  }
  return esquemaListo;
}

const todas = async (env, sql, ...args) => (await env.DB.prepare(sql).bind(...args).all()).results;
const una = async (env, sql, ...args) => (await todas(env, sql, ...args))[0] ?? null;
const ejecutar = (env, sql, ...args) => env.DB.prepare(sql).bind(...args).run();

const json = (data, status = 200, headers = {}) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });

/* ---------- Criptografía: contraseñas y llaves (JWT) ---------- */

const enc = new TextEncoder();
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const deB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const aleatorio = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (texto) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(texto)));

// Las iteraciones se guardan con cada contraseña para poder subirlas más adelante.
const ITERACIONES = 50000;
async function pbkdf2(password, sal, iteraciones) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: sal, iterations: iteraciones }, base, 256));
}
async function cifrarPassword(password) {
  const sal = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITERACIONES}$${b64url(sal)}$${b64url(await pbkdf2(password, sal, ITERACIONES))}`;
}
async function comprobarPassword(password, guardado) {
  const [alg, iter, sal, hash] = String(guardado).split("$");
  if (alg !== "pbkdf2") return false;
  const calculado = b64url(await pbkdf2(password, deB64url(sal), Number(iter)));
  let dif = calculado.length ^ hash.length;
  for (let i = 0; i < calculado.length; i++) dif |= calculado.charCodeAt(i) ^ hash.charCodeAt(i % hash.length);
  return dif === 0;
}
// Comparación que tarda lo mismo aunque los textos se parezcan.
function iguales(a, b) {
  a = String(a);
  b = String(b);
  let dif = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i % (b.length || 1));
  return dif === 0;
}

// Código de recuperación: 16 letras y números sin los que se confunden (0, O, 1, I),
// escritas en grupos de 4. Son 80 bits al azar, imposibles de adivinar.
const ALFABETO_CODIGO = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const nuevoCodigo = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => ALFABETO_CODIGO[b % 32])
    .join("")
    .match(/.{4}/g)
    .join("-");
const limpiarCodigo = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const hashCodigo = (c) => sha256(limpiarCodigo(c));

// Contraseña de relleno para tardar lo mismo cuando el correo no existe.
const PASSWORD_FALSA = `pbkdf2$${ITERACIONES}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

// Clave para firmar las llaves: la variable secreta JWT_SECRET si existe; si no, una
// generada al azar la primera vez y guardada en la propia base de datos.
let claveFirma = null;
function obtenerClave(env) {
  if (!claveFirma) {
    claveFirma = (async () => {
      let secreto = env.JWT_SECRET;
      if (!secreto) {
        await ejecutar(env, "INSERT OR IGNORE INTO ajustes (clave, valor) VALUES ('jwt_secret', ?)", aleatorio(48));
        secreto = (await una(env, "SELECT valor FROM ajustes WHERE clave = 'jwt_secret'")).valor;
      }
      return crypto.subtle.importKey("raw", enc.encode(secreto), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    })().catch((err) => {
      claveFirma = null;
      throw err;
    });
  }
  return claveFirma;
}

const DURACION_S = 3600;
const segundos = () => Math.floor(Date.now() / 1000);

async function firmarLlave(env, usuario) {
  const cabecera = b64url(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const cuerpo = b64url(enc.encode(JSON.stringify({
    sub: usuario.id,
    email: usuario.email,
    iat: segundos(),
    exp: segundos() + DURACION_S,
    app_metadata: usuario.app_metadata,
    user_metadata: usuario.user_metadata,
  })));
  const firma = await crypto.subtle.sign("HMAC", await obtenerClave(env), enc.encode(`${cabecera}.${cuerpo}`));
  return `${cabecera}.${cuerpo}.${b64url(firma)}`;
}

// Devuelve el contenido de la llave del encabezado Authorization si es válida.
async function leerLlave(env, req) {
  const m = (req.headers.get("authorization") || "").match(/^Bearer (\S+)$/i);
  const partes = m?.[1].split(".");
  if (partes?.length !== 3) return null;
  try {
    const valida = await crypto.subtle.verify("HMAC", await obtenerClave(env), deB64url(partes[2]), enc.encode(`${partes[0]}.${partes[1]}`));
    if (!valida) return null;
    const datos = JSON.parse(new TextDecoder().decode(deB64url(partes[1])));
    return typeof datos.sub === "string" && datos.exp > segundos() ? datos : null;
  } catch {
    return null;
  }
}

/* ---------- Acceso con cuenta (/.netlify/identity) ---------- */

const normalizar = (email) => String(email || "").trim().toLowerCase();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Una sesión sin usar durante este tiempo se cierra.
const SESION_DIAS = 90;

const comoUsuario = (fila) => ({
  id: fila.id,
  aud: "",
  role: "",
  email: fila.email,
  confirmed_at: fila.creado_at,
  created_at: fila.creado_at,
  updated_at: fila.actualizado_at,
  // "codigo_recuperacion" le avisa a la pantalla que esta versión tiene código de recuperación.
  app_metadata: { provider: "email", codigo_recuperacion: true },
  user_metadata: JSON.parse(fila.user_metadata || "{}"),
});
const buscarUsuario = (env, campo, valor) => una(env, `SELECT * FROM usuarios WHERE ${campo} = ?`, valor);

async function abrirSesion(env, usuario, refresh, extra = {}) {
  if (!refresh) {
    refresh = aleatorio(32);
    await ejecutar(env, "INSERT INTO sesiones (token_hash, user_id) VALUES (?, ?)", await sha256(refresh), usuario.id);
  }
  return json({ access_token: await firmarLlave(env, usuario), token_type: "bearer", expires_in: DURACION_S, refresh_token: refresh, ...extra });
}

// Crea (o reemplaza) el código de recuperación de una cuenta y lo devuelve en claro:
// es la única vez que se puede ver.
async function guardarCodigo(env, userId) {
  const codigo = nuevoCodigo();
  await ejecutar(env, "INSERT OR REPLACE INTO recuperacion (user_id, codigo_hash) VALUES (?, ?)", userId, await hashCodigo(codigo));
  return codigo;
}

// Pone una contraseña nueva, cierra las sesiones abiertas y cambia el código de recuperación.
// Devuelve el código nuevo.
async function reiniciarCuenta(env, userId, password) {
  const codigo = nuevoCodigo();
  await env.DB.batch([
    env.DB.prepare(`UPDATE usuarios SET password_hash = ?, actualizado_at = ${AHORA} WHERE id = ?`).bind(await cifrarPassword(password), userId),
    env.DB.prepare("DELETE FROM sesiones WHERE user_id = ?").bind(userId),
    env.DB.prepare("INSERT OR REPLACE INTO recuperacion (user_id, codigo_hash) VALUES (?, ?)").bind(userId, await hashCodigo(codigo)),
  ]);
  return codigo;
}

const credencialesMal = () => json({ error: "invalid_grant", error_description: "Invalid login credentials" }, 400);

async function identidad(req, env, ruta) {
  if (ruta === "/token" && req.method === "POST") {
    const form = new URLSearchParams(await req.text());
    if (form.get("grant_type") === "password") {
      const fila = await buscarUsuario(env, "email", normalizar(form.get("username")));
      const ok = await comprobarPassword(form.get("password") || "", fila?.password_hash || PASSWORD_FALSA);
      return fila && ok ? abrirSesion(env, comoUsuario(fila)) : credencialesMal();
    }
    if (form.get("grant_type") === "refresh_token") {
      const refresh = form.get("refresh_token") || "";
      const hash = await sha256(refresh);
      const fila = await una(
        env,
        `SELECT u.* FROM sesiones s JOIN usuarios u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.usada_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`,
        hash,
        `-${SESION_DIAS} days`,
      );
      if (!fila) return json({ error: "invalid_grant", error_description: "Invalid Refresh Token" }, 400);
      await ejecutar(env, `UPDATE sesiones SET usada_at = ${AHORA} WHERE token_hash = ?`, hash);
      return abrirSesion(env, comoUsuario(fila), refresh);
    }
    return json({ error: "unsupported_grant_type", error_description: "Tipo de acceso no válido" }, 400);
  }

  if (ruta === "/signup" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    const email = normalizar(body?.email);
    const password = typeof body?.password === "string" ? body.password : "";
    if (!EMAIL_RE.test(email) || password.length < 6) {
      return json({ code: 422, msg: "Password should be at least 6 characters and email must be valid" }, 422);
    }
    // CORREOS_PERMITIDOS (opcional): lista de correos separados por comas que pueden registrarse.
    const permitidos = String(env.CORREOS_PERMITIDOS || "").split(",").map(normalizar).filter(Boolean);
    if (permitidos.length && !permitidos.includes(email)) {
      return json({ code: 403, msg: "Signups not allowed for this instance" }, 403);
    }
    const datos = body?.data && typeof body.data === "object" ? body.data : {};
    const metadata = {};
    for (const k of ["full_name", "nombre", "apellido"]) if (typeof datos[k] === "string") metadata[k] = datos[k].slice(0, 200);
    const res = await env.DB.prepare("INSERT OR IGNORE INTO usuarios (id, email, password_hash, user_metadata) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), email, await cifrarPassword(password), JSON.stringify(metadata))
      .run();
    if (!res.meta.changes) return json({ code: 400, msg: "A user with this email address has already been registered" }, 400);
    // No hay correo de confirmación: la cuenta queda confirmada al crearla.
    const nueva = await buscarUsuario(env, "email", email);
    return json({ ...comoUsuario(nueva), recovery_code: await guardarCodigo(env, nueva.id) });
  }

  if (ruta === "/user" && (req.method === "GET" || req.method === "PUT")) {
    const llave = await leerLlave(env, req);
    const fila = llave && (await buscarUsuario(env, "id", llave.sub));
    if (!fila) return json({ code: 401, msg: "Invalid token" }, 401);
    if (req.method === "GET") return json(comoUsuario(fila));
    const body = await req.json().catch(() => null);
    if (body?.password !== undefined) {
      if (typeof body.password !== "string" || body.password.length < 6) {
        return json({ code: 422, msg: "Password should be at least 6 characters" }, 422);
      }
      await ejecutar(env, `UPDATE usuarios SET password_hash = ?, actualizado_at = ${AHORA} WHERE id = ?`, await cifrarPassword(body.password), fila.id);
    }
    return json(comoUsuario(await buscarUsuario(env, "id", fila.id)));
  }

  if (ruta === "/logout" && req.method === "POST") {
    const llave = await leerLlave(env, req);
    if (llave) await ejecutar(env, "DELETE FROM sesiones WHERE user_id = ?", llave.sub);
    return new Response(null, { status: 204 });
  }

  // Código de recuperación nuevo para la cuenta con la sesión abierta. Pide la contraseña
  // para que nadie con el móvil desbloqueado pueda cambiarlo. El código anterior deja de valer.
  if (ruta === "/recovery-code" && req.method === "POST") {
    const llave = await leerLlave(env, req);
    const fila = llave && (await buscarUsuario(env, "id", llave.sub));
    if (!fila) return json({ code: 401, msg: "Invalid token" }, 401);
    const body = await req.json().catch(() => null);
    const ok = await comprobarPassword(typeof body?.password === "string" ? body.password : "", fila.password_hash);
    if (!ok) return json({ code: 403, msg: "Invalid password" }, 403);
    return json({ recovery_code: await guardarCodigo(env, fila.id) });
  }

  if (ruta === "/recover" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    // Sin código, es el aviso de que esta versión no envía correos: la pantalla pasa a pedir el código.
    if (!body?.recovery_code) {
      return json({ code: 501, msg: "En esta versión no se puede recuperar la contraseña por correo. Usa tu código de recuperación." }, 501);
    }
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length < 6) return json({ code: 422, msg: "Password should be at least 6 characters" }, 422);
    const fila = await buscarUsuario(env, "email", normalizar(body.email));
    const guardado = fila && (await una(env, "SELECT codigo_hash FROM recuperacion WHERE user_id = ?", fila.id));
    // Mismo error si el correo no existe o el código no coincide.
    if (!guardado || !iguales(guardado.codigo_hash, await hashCodigo(body.recovery_code))) {
      return json({ code: 400, msg: "Invalid recovery code", error_description: "Invalid recovery code" }, 400);
    }
    const codigo = await reiniciarCuenta(env, fila.id, password);
    return abrirSesion(env, comoUsuario(await buscarUsuario(env, "id", fila.id)), null, { recovery_code: codigo });
  }

  if (ruta === "/recover" || ruta === "/verify") {
    return json({ code: 501, msg: "En esta versión no se puede recuperar la contraseña por correo." }, 501);
  }

  return json({ code: 404, msg: "Not found" }, 404);
}

/* ---------- Datos: jornadas, registros y abonos (/api/*) ---------- */

// "Ingreso" ya no se registra desde la app, pero los registros antiguos siguen sumando.
const TIPOS = ["Efectivo", "Tarjeta", "Gasto", "Ingreso en banco"];
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;

const hoy = () => new Date().toISOString().slice(0, 10);
// Fecha válida para una jornada: con formato correcto y que no sea futura (se deja un
// día de margen porque el servidor usa UTC y el móvil la hora local).
function fechaValida(v) {
  if (typeof v !== "string" || !FECHA_RE.test(v) || Number.isNaN(Date.parse(v))) return null;
  const manana = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  return v <= manana ? v : null;
}

// Columnas con los mismos nombres y formatos que devuelve la versión de Netlify.
const dinero = (col) => `CASE WHEN ${col} IS NULL THEN NULL ELSE printf('%.2f', ${col}) END`;
const COLS_JORNADA = `id, user_id AS userId, abierta_at AS abiertaAt, cerrada_at AS cerradaAt,
  ${dinero("te_tengo_manual")} AS teTengoManual, ${dinero("me_tienes_manual")} AS meTienesManual, fecha`;
const COLS_MOV = `id, user_id AS userId, jornada_id AS jornadaId, tipo, printf('%.2f', monto) AS monto, fecha, nota, created_at AS createdAt`;
const COLS_PAGO = `id, user_id AS userId, tipo, printf('%.2f', monto) AS monto, nota, created_at AS createdAt`;
// Día de una jornada: el cargado o, en las antiguas, el día en que se registró.
const DIA_JORNADA = "coalesce(j.fecha, date(j.cerrada_at))";

const sumaTipo = (tipo, alias) => `coalesce(sum(CASE WHEN m.tipo = '${tipo}' THEN m.monto ELSE 0 END), 0) AS ${alias}`;
const SUMAS = [
  sumaTipo("Ingreso", "otros"),
  sumaTipo("Efectivo", "efectivo"),
  sumaTipo("Tarjeta", "tarjeta"),
  sumaTipo("Gasto", "gastos"),
  sumaTipo("Ingreso en banco", "banco"),
].join(", ");

// Lo ganado suma los ingresos generales, en efectivo y con tarjeta.
const ganado = (f) => Number(f.otros) + Number(f.efectivo) + Number(f.tarjeta);

function totales(f) {
  const ingresos = ganado(f);
  const gastos = Number(f.gastos);
  const total = ingresos - gastos;
  return {
    ingresos,
    otros: Number(f.otros),
    efectivo: Number(f.efectivo),
    tarjeta: Number(f.tarjeta),
    gastos,
    banco: Number(f.banco),
    total,
    mitad: total / 2,
  };
}

// Saldo automático entre socios de un grupo de registros, visto desde el conductor.
// Cada socio se queda con el 50% de lo ganado. Lo cobrado con tarjeta lo recibe el
// otro socio; el efectivo (menos los gastos, que se pagan de él) lo guarda el
// conductor, y lo ingresado en el banco se le entrega al otro socio.
// Positivo = "Te tengo" (el conductor guarda dinero del otro); negativo = "Me tienes".
const saldoAuto = (f) =>
  (Number(f.otros) + Number(f.efectivo) - Number(f.gastos) - Number(f.tarjeta)) / 2 - Number(f.banco);
const separar = (saldo) => ({ teTengo: saldo > 0 ? saldo : 0, meTienes: saldo < 0 ? -saldo : 0 });

// Saldo entre socios de cada jornada del usuario. Cada jornada empieza en 0: el saldo
// sale solo de sus registros, o de los valores cargados a mano si los tiene.
async function saldos(env, userId) {
  const porJornada = await todas(env, `SELECT m.jornada_id AS jornadaId, ${SUMAS} FROM movimientos m WHERE m.user_id = ? GROUP BY m.jornada_id`, userId);
  const lista = await todas(env, "SELECT id, te_tengo_manual AS te, me_tienes_manual AS me FROM jornadas WHERE user_id = ?", userId);
  const sumasDe = new Map(porJornada.map((f) => [f.jornadaId, f]));
  const resultado = new Map();
  for (const j of lista) {
    if (j.te != null || j.me != null) {
      resultado.set(j.id, { teTengo: Number(j.te ?? 0), meTienes: Number(j.me ?? 0), manual: true });
      continue;
    }
    const f = sumasDe.get(j.id);
    resultado.set(j.id, { ...separar(f ? saldoAuto(f) : 0), manual: false });
  }
  return resultado;
}

const r2 = (n) => Math.round(n * 100) / 100;
// Cuentas entre socios y el tipo con que se guardan sus abonos.
const CUENTAS = { teTengo: "te_tengo", meTienes: "me_tienes" };
const NOTA_ABONO = { teTengo: "Te he pagado", meTienes: "Me has pagado" };

// Lo pendiente entre socios: la suma de "Te tengo" / "Me tienes" de todas las jornadas
// (también la abierta) menos lo ya abonado. Registrar una jornada no lo borra; solo
// baja con los abonos.
async function pendientes(env, userId) {
  const suma = { teTengo: 0, meTienes: 0 };
  for (const s of (await saldos(env, userId)).values()) {
    suma.teTengo += s.teTengo;
    suma.meTienes += s.meTienes;
  }
  const abonos = await todas(env, "SELECT tipo, coalesce(sum(monto), 0) AS pagado FROM pagos_socio WHERE user_id = ? GROUP BY tipo", userId);
  const cuenta = (c) => {
    const pagado = Number(abonos.find((a) => a.tipo === CUENTAS[c])?.pagado ?? 0);
    return { suma: r2(suma[c]), pagado: r2(pagado), total: r2(suma[c] - pagado) };
  };
  return { teTengo: cuenta("teTengo"), meTienes: cuenta("meTienes") };
}
const totalesPendientes = async (env, userId) => {
  const p = await pendientes(env, userId);
  return { teTengo: p.teTengo.total, meTienes: p.meTienes.total };
};

// Resumen de una jornada y su saldo entre socios.
async function resumen(env, userId, jornadaId) {
  const jor = await una(env, `SELECT ${SUMAS} FROM movimientos m WHERE m.user_id = ? AND m.jornada_id = ?`, userId, jornadaId);
  const saldo = (await saldos(env, userId)).get(jornadaId) ?? { teTengo: 0, meTienes: 0, manual: false };
  return { ...totales(jor), ...saldo };
}

// Devuelve la jornada abierta del usuario, creándola si no existe.
async function jornadaAbierta(env, userId) {
  const buscar = () => una(env, `SELECT ${COLS_JORNADA} FROM jornadas WHERE user_id = ? AND cerrada_at IS NULL LIMIT 1`, userId);
  let jornada = await buscar();
  if (!jornada) {
    await ejecutar(env, "INSERT OR IGNORE INTO jornadas (user_id) VALUES (?)", userId);
    jornada = await buscar();
  }
  return jornada;
}

const contarRegistros = async (env, userId, jornadaId) =>
  (await una(env, "SELECT count(*) AS n FROM movimientos WHERE user_id = ? AND jornada_id = ?", userId, jornadaId)).n;

function leerMovimiento(body) {
  const tipo = TIPOS.find((t) => t === body?.tipo);
  if (!tipo) return { error: "Tipo de movimiento no válido" };
  const monto = Number(body?.monto);
  if (!Number.isFinite(monto) || monto <= 0) return { error: "El monto debe ser mayor que 0" };
  const fecha = typeof body?.fecha === "string" && FECHA_RE.test(body.fecha) ? body.fecha : hoy();
  const nota = typeof body?.nota === "string" ? body.nota.slice(0, 500) : "";
  return { valores: { tipo, monto: Number(monto.toFixed(2)), fecha, nota } };
}

const BLOQUEADO = "Este registro pertenece a una jornada ya registrada y no se puede modificar.";
const YA_REGISTRADA = "Esta jornada ya se registró. Recarga la pantalla.";

async function datos(req, env, ruta) {
  const llave = await leerLlave(env, req);
  if (!llave) return json({ error: "Inicia sesión para continuar" }, 401);
  const userId = llave.sub;
  const url = new URL(req.url);
  const id = Number(url.searchParams.get("id"));
  const idValido = Number.isInteger(id) && id > 0;

  /* ----- Abonos entre socios: "Te he pagado" / "Me has pagado" ----- */
  if (ruta === "/api/me-tienes" || ruta === "/api/pagos") {
    if (req.method === "GET") {
      const pagos = await todas(env, `SELECT ${COLS_PAGO} FROM pagos_socio WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 100`, userId);
      return json({ ...(await pendientes(env, userId)), pagos });
    }
    if (req.method === "POST") {
      // { cuenta, pago } abona a esa cuenta; { cuenta, total } fija el pendiente a mano.
      const body = await req.json().catch(() => null);
      const cuenta = body?.cuenta === "teTengo" ? "teTengo" : "meTienes";
      const nota = typeof body?.nota === "string" ? body.nota.trim().slice(0, 500) : "";
      let monto;
      if (body?.total !== undefined) {
        const total = Number(body.total);
        if (body.total === "" || !Number.isFinite(total) || total < 0) {
          return json({ error: "El total debe ser un número de 0 o más" }, 400);
        }
        monto = (await pendientes(env, userId))[cuenta].total - total;
      } else {
        monto = Number(body?.pago);
        if (!Number.isFinite(monto) || monto <= 0) return json({ error: "El pago debe ser mayor que 0" }, 400);
      }
      if (Math.abs(monto) >= 0.005) {
        await ejecutar(
          env,
          "INSERT INTO pagos_socio (user_id, tipo, monto, nota) VALUES (?, ?, ?, ?)",
          userId,
          CUENTAS[cuenta],
          Number(monto.toFixed(2)),
          nota || (body?.total !== undefined ? "Total ajustado a mano" : NOTA_ABONO[cuenta]),
        );
      }
      return json(await pendientes(env, userId), 201);
    }
    return new Response("Method not allowed", { status: 405 });
  }

  /* ----- Historial de jornadas ----- */
  if (ruta === "/api/jornadas") {
    if (req.method === "GET" && idValido) {
      const jornada = await una(env, `SELECT ${COLS_JORNADA} FROM jornadas WHERE id = ? AND user_id = ?`, id, userId);
      if (!jornada) return json({ error: "Jornada no encontrada" }, 404);
      const rows = await todas(env, `SELECT ${COLS_MOV} FROM movimientos WHERE user_id = ? AND jornada_id = ? ORDER BY created_at DESC, id DESC`, userId, id);
      return json({ jornada, resumen: await resumen(env, userId, id), movimientos: rows });
    }
    if (req.method === "GET") {
      // ?mes=AAAA-MM devuelve el cierre de ese mes y ?desde=…&hasta=… el resumen de esas
      // fechas: sus jornadas registradas y los totales.
      const mes = url.searchParams.get("mes");
      if (mes !== null && !/^\d{4}-(0[1-9]|1[0-2])$/.test(mes)) return json({ error: "Mes no válido" }, 400);
      let desde = null;
      let hasta = null;
      if (mes) {
        desde = `${mes}-01`;
        const [y, m] = mes.split("-").map(Number);
        hasta = new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10);
      } else if (url.searchParams.has("desde") || url.searchParams.has("hasta")) {
        const leer = (v) => (v && FECHA_RE.test(v) && !Number.isNaN(Date.parse(v)) ? v : null);
        desde = leer(url.searchParams.get("desde"));
        hasta = leer(url.searchParams.get("hasta"));
        if (!desde || !hasta) return json({ error: "Elige las dos fechas" }, 400);
        if (desde > hasta) return json({ error: "La fecha «Desde» debe ser anterior a «Hasta»" }, 400);
      }
      const rango = desde !== null && hasta !== null;
      const orden = rango ? "ASC" : "DESC";
      const filas = await todas(
        env,
        `SELECT j.id, ${DIA_JORNADA} AS dia, j.abierta_at AS abiertaAt, j.cerrada_at AS cerradaAt, ${SUMAS}
         FROM jornadas j LEFT JOIN movimientos m ON m.jornada_id = j.id
         WHERE j.user_id = ? AND j.cerrada_at IS NOT NULL ${rango ? `AND ${DIA_JORNADA} BETWEEN ? AND ?` : ""}
         GROUP BY j.id
         ORDER BY dia ${orden}, j.cerrada_at ${orden}
         LIMIT ${rango ? 2000 : 200}`,
        ...(rango ? [userId, desde, hasta] : [userId]),
      );
      const saldoDe = await saldos(env, userId);
      const lista = filas.map((f) => ({
        id: f.id,
        fecha: f.dia,
        abiertaAt: f.abiertaAt,
        cerradaAt: f.cerradaAt,
        ...totales(f),
        ...(saldoDe.get(f.id) ?? { teTengo: 0, meTienes: 0, manual: false }),
      }));
      if (!rango) return json({ jornadas: lista });
      const suma = (k) => Math.round(lista.reduce((t, j) => t + j[k], 0) * 100) / 100;
      const t = totales({ otros: suma("otros"), efectivo: suma("efectivo"), tarjeta: suma("tarjeta"), gastos: suma("gastos"), banco: suma("banco") });
      const abierta = await jornadaAbierta(env, userId);
      const sinRegistrar = await contarRegistros(env, userId, abierta.id);
      const diaAbierta = abierta.fecha ?? hoy();
      // Abonos hechos dentro del periodo (por el día en que se registraron).
      const abonos = await todas(
        env,
        `SELECT tipo, printf('%.2f', monto) AS monto, nota, created_at AS createdAt FROM pagos_socio
         WHERE user_id = ? AND date(created_at) BETWEEN ? AND ? ORDER BY created_at ASC, id ASC`,
        userId,
        desde,
        hasta,
      );
      return json({
        mes,
        desde,
        hasta,
        jornadas: lista,
        abonos,
        resumen: { ...t, teTengo: suma("teTengo"), meTienes: suma("meTienes"), dias: new Set(lista.map((j) => j.fecha)).size },
        // La jornada abierta todavía no entra en el resumen; se avisa si es del periodo.
        abiertaPendiente: sinRegistrar > 0 && diaAbierta >= desde && diaAbierta <= hasta,
        pendientes: await totalesPendientes(env, userId),
      });
    }
    if (req.method === "POST") {
      // Registrar (cerrar) la jornada abierta y abrir una nueva.
      const body = await req.json().catch(() => null);
      const abierta = await jornadaAbierta(env, userId);
      if (Number(body?.jornadaId) !== abierta.id) return json({ error: YA_REGISTRADA }, 409);
      if (!(await contarRegistros(env, userId, abierta.id))) return json({ error: "La jornada no tiene registros todavía." }, 400);
      // La jornada queda registrada en su día (puede ser un día anterior) y sus
      // registros toman esa misma fecha.
      const fecha = fechaValida(body?.fecha) ?? abierta.fecha ?? hoy();
      const [, cierre] = await env.DB.batch([
        env.DB.prepare("UPDATE movimientos SET fecha = ? WHERE user_id = ? AND jornada_id = ?").bind(fecha, userId, abierta.id),
        env.DB.prepare(`UPDATE jornadas SET cerrada_at = ?, fecha = ? WHERE id = ? AND user_id = ? AND cerrada_at IS NULL RETURNING ${COLS_JORNADA}`)
          .bind(new Date().toISOString(), fecha, abierta.id, userId),
      ]);
      const cerrada = cierre.results[0];
      if (!cerrada) return json({ error: YA_REGISTRADA }, 409);
      const nueva = await jornadaAbierta(env, userId);
      return json({ cerrada, nueva }, 201);
    }
    if (req.method === "PUT") {
      // Cargar a mano "Te tengo" / "Me tienes" de la jornada abierta (null = automático).
      const body = await req.json().catch(() => null);
      const abierta = await jornadaAbierta(env, userId);
      if (Number(body?.jornadaId) !== abierta.id) return json({ error: YA_REGISTRADA }, 409);
      if (body && "fecha" in body) {
        // Cambiar el día de la jornada abierta (para cargar un día anterior).
        const fecha = fechaValida(body.fecha);
        if (!fecha) return json({ error: "Elige un día de hoy o anterior" }, 400);
        await env.DB.batch([
          env.DB.prepare("UPDATE jornadas SET fecha = ? WHERE id = ? AND user_id = ? AND cerrada_at IS NULL").bind(fecha, abierta.id, userId),
          env.DB.prepare("UPDATE movimientos SET fecha = ? WHERE user_id = ? AND jornada_id = ?").bind(fecha, userId, abierta.id),
        ]);
        return json({ fecha });
      }
      const leerValor = (v) => {
        if (v === null || v === undefined || v === "") return null;
        const n = Number(v);
        return Number.isFinite(n) && n >= 0 ? Number(n.toFixed(2)) : undefined;
      };
      const teTengoManual = leerValor(body?.teTengo);
      const meTienesManual = leerValor(body?.meTienes);
      if (teTengoManual === undefined || meTienesManual === undefined) {
        return json({ error: "Los montos deben ser números de 0 o más" }, 400);
      }
      await ejecutar(
        env,
        "UPDATE jornadas SET te_tengo_manual = ?, me_tienes_manual = ? WHERE id = ? AND user_id = ? AND cerrada_at IS NULL",
        teTengoManual,
        meTienesManual,
        abierta.id,
        userId,
      );
      return json({ resumen: await resumen(env, userId, abierta.id) });
    }
    return new Response("Method not allowed", { status: 405 });
  }

  /* ----- Registros de la jornada abierta (/api/movimientos) ----- */
  if (req.method === "GET" && url.searchParams.has("todo")) {
    const rows = await todas(
      env,
      `SELECT m.fecha, m.tipo, printf('%.2f', m.monto) AS monto, m.nota, j.abierta_at AS abiertaAt, j.cerrada_at AS cerradaAt
       FROM movimientos m LEFT JOIN jornadas j ON j.id = m.jornada_id
       WHERE m.user_id = ? ORDER BY m.jornada_id ASC, m.created_at ASC, m.id ASC`,
      userId,
    );
    return json({ movimientos: rows });
  }

  const abierta = await jornadaAbierta(env, userId);

  if (req.method === "GET") {
    const rows = await todas(env, `SELECT ${COLS_MOV} FROM movimientos WHERE user_id = ? AND jornada_id = ? ORDER BY created_at DESC, id DESC`, userId, abierta.id);
    return json({
      jornada: abierta,
      resumen: await resumen(env, userId, abierta.id),
      pendientes: await totalesPendientes(env, userId),
      movimientos: rows,
    });
  }

  if (req.method === "POST" || req.method === "PUT") {
    const leido = leerMovimiento(await req.json().catch(() => null));
    if (!leido.valores) return json({ error: leido.error }, 400);
    const { tipo, monto, nota } = leido.valores;
    const fecha = abierta.fecha ?? leido.valores.fecha;
    if (req.method === "POST") {
      const row = await una(
        env,
        `INSERT INTO movimientos (user_id, jornada_id, tipo, monto, fecha, nota) VALUES (?, ?, ?, ?, ?, ?) RETURNING ${COLS_MOV}`,
        userId,
        abierta.id,
        tipo,
        monto,
        fecha,
        nota,
      );
      return json(row, 201);
    }
    if (!idValido) return json({ error: "Id no válido" }, 400);
    const row = await una(
      env,
      `UPDATE movimientos SET tipo = ?, monto = ?, fecha = ?, nota = ? WHERE id = ? AND user_id = ? AND jornada_id = ? RETURNING ${COLS_MOV}`,
      tipo,
      monto,
      fecha,
      nota,
      id,
      userId,
      abierta.id,
    );
    if (!row) return json({ error: BLOQUEADO }, 409);
    return json(row);
  }

  if (req.method === "DELETE") {
    if (!idValido) return json({ error: "Id no válido" }, 400);
    const res = await ejecutar(env, "DELETE FROM movimientos WHERE id = ? AND user_id = ? AND jornada_id = ?", id, userId, abierta.id);
    if (!res.meta.changes) return json({ error: BLOQUEADO }, 409);
    return new Response(null, { status: 204 });
  }

  return new Response("Method not allowed", { status: 405 });
}

/* ---------- Restablecer contraseñas como administrador ---------- */

// Página sencilla para poner una contraseña nueva a una cuenta desde el móvil. Solo existe
// si el Worker tiene la variable secreta ADMIN_KEY (de 16 caracteres o más).
const RUTA_ADMIN = "/api/admin-restablecer";
const PAGINA_ADMIN = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Restablecer contraseña</title>
<style>body{font:16px system-ui,sans-serif;max-width:420px;margin:2rem auto;padding:0 1rem}
form{display:grid;gap:.8rem}input,button{font:inherit;padding:.7rem;border-radius:8px;border:1px solid #bbb}
button{background:#111;color:#fff;border:0;font-weight:600}#salida{margin-top:1rem;word-break:break-word}
.codigo{font:700 1.3rem ui-monospace,monospace;letter-spacing:.05em}</style></head><body>
<h1>Restablecer contraseña</h1>
<form id="f">
<label>Clave de administrador<input name="clave" type="password" autocomplete="off" required></label>
<label>Correo de la cuenta<input name="email" type="email" autocapitalize="off" required></label>
<label>Contraseña nueva<input name="password" type="text" autocomplete="off" minlength="6" required></label>
<button>Cambiar contraseña</button>
</form>
<p id="salida"></p>
<script>
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, s = document.getElementById("salida");
  s.textContent = "Enviando…";
  try {
    const r = await fetch("${RUTA_ADMIN}", { method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + f.clave.value },
      body: JSON.stringify({ email: f.email.value, password: f.password.value }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { s.textContent = d.error || "Error " + r.status; return; }
    s.textContent = "Listo. Contraseña cambiada. Código de recuperación nuevo de esa cuenta: ";
    const c = document.createElement("div"); c.className = "codigo"; c.textContent = d.recovery_code;
    s.appendChild(c);
    f.password.value = "";
  } catch { s.textContent = "Sin conexión."; }
});
</script></body></html>`;

async function administrador(req, env) {
  // Sin ADMIN_KEY (o con una demasiado corta) esta función no existe.
  if (String(env.ADMIN_KEY || "").length < 16) return json({ error: "No encontrado" }, 404);
  if (req.method === "GET") {
    return new Response(PAGINA_ADMIN, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
  }
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const clave = (req.headers.get("authorization") || "").match(/^Bearer (.+)$/i)?.[1] || "";
  if (!iguales(await sha256(clave), await sha256(env.ADMIN_KEY))) return json({ error: "Clave de administrador no válida" }, 401);
  const body = await req.json().catch(() => null);
  const password = typeof body?.password === "string" ? body.password : "";
  if (password.length < 6) return json({ error: "La contraseña nueva debe tener al menos 6 caracteres" }, 422);
  const fila = await buscarUsuario(env, "email", normalizar(body?.email));
  if (!fila) return json({ error: "No hay ninguna cuenta con ese correo" }, 404);
  return json({ ok: true, email: fila.email, recovery_code: await reiniciarCuenta(env, fila.id, password) });
}

/* ---------- Entrada del Worker ---------- */

const RUTAS_API = ["/api/movimientos", "/api/jornadas", "/api/me-tienes", "/api/pagos"];
const IDENTITY = "/.netlify/identity";

export default {
  async fetch(req, env) {
    const ruta = new URL(req.url).pathname.replace(/\/+$/, "");
    const esIdentidad = ruta.startsWith(IDENTITY);
    const esAdmin = ruta === RUTA_ADMIN;
    if (!esIdentidad && !esAdmin && !RUTAS_API.includes(ruta)) return env.ASSETS.fetch(req);
    try {
      await prepararEsquema(env);
      if (esAdmin) return await administrador(req, env);
      return esIdentidad ? await identidad(req, env, ruta.slice(IDENTITY.length)) : await datos(req, env, ruta);
    } catch (err) {
      console.error("Error en el servidor", err);
      return esIdentidad
        ? json({ code: 500, msg: "No se pudo completar el acceso. Inténtalo de nuevo." }, 500)
        : json({ error: "No se pudo guardar o leer los datos. Inténtalo de nuevo." }, 500);
    }
  },
};
