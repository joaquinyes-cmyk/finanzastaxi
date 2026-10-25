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

/* ---------- Iconos de la app (PNG) ---------- */

// Los iconos del logo van dentro del Worker, así no hace falta subir archivos PNG al
// repositorio. Se responden desde estas direcciones (también están en run_worker_first
// de wrangler.jsonc, para que Cloudflare las pase por aquí).
const ICONOS = {
  "/apple-touch-icon.png": "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",
  "/favicon-48.png": "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",
  "/icon-192.png": "iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAMAAABlApw1AAADAFBMVEX8/P32+Pj08/Tv8PHu7fDs7e/r6u3o6ezz8ufp6ern5unk5Of488Du5tn77ob+7ibn4uHx3a/r1ajqyqb213772iTxzGrrwVf/4Qn+3An+2An+0wj8zQj1zA3wxBDovg7S8bXc4tje3+La3szb2tvQ19vT1dLX1qvUz8vKzc/HxsjGwcHZy6nUwKTZx4Pav06y9KOy4p+a7YeR23+7zM2wz4SWz31+z3S6w8i+v8W9vr++v7GtwMqpwamXwYB2wWrcsn7JsYe6ubu8sJ7jtyThrT7UsC/Qpz22tbirtbyysbSsrrWvr66xr6KpqKyqp6LOnWy3mXanop+rmHbQoUDLl0G8mi62kzPAjFTBjDewjV6uiyeugk60gzKreUSseCqdrqygoqGenqKdnZacmp2Yl5uXlZeblHePo6eOq3GRkZeQj4qCp21sqkl7lJt0lVqQiIGFhoyKgnmQeXGehieXfTKYdjOMdi56hJB4eYd3gGN2dG5je5FReoJhgl9edlCQaFiUaTecaiSLYyJybmtwZ2x5ZzV7ZhF3XyeCWUuDWCRvWUBvTzeHVxlvWRCBTw9yShFgZ3NfXmRdZFNdVkBRZ2I/ZGVTV1RAWVxSUUxQSkdgTxVYRhxFSU4tS189TDs/RTxdPh5MPh9EPztGOhM8PkE5OT44OzQ3Ni1KMBY8Lxg2MCU0KBMvMTIvMCkvKh8vIhEfNkMkMygoKiwfKislJScZJCwoIxMcJBslIBQfHyAjGxAdHBobHRwaGhoTHBoeFw0ZFxYWFhYfEQwVEQ0UExISFRQSEhIREREREA0RDAcNExEODw8ODg4NDQwNDA0NCwcLCwsKCgsLCQcJCQkKBgQHDA0HCAcHBwYGBgYGBgQEBgYHBQYFBQUGBQMEBAQDBAMGAwMEAwMEAwAFAgMDAwQDAwMDAgQDAwEDAgEBCQwCAwMCAwECAgQCAgIBAgICAgECAgABAgEBAQMCAQEBAQEAAQECAQABAQAAAQADAAEBAAIBAAAAAAMAAAEAAACNbJebAAAdp0lEQVR42u2cCziU6R7AXdJNnEKISivkOilULrnV7iJNFK27yD10XE7b5DZuyTWmtlkJyd0a0TSqkWuFJLemRbvS1q5Y26zkK3bxP+83qrPn7HnOk5bO7vPM+9TXN/Pd/r/3f32/95144C/eeLgAXAAuABeAC8AF4AJwAbgAXAAuABeAC8AF4AJwAbgAXAAuABeAC8AF4AJwAbgAXIA/BcAw+68NMAqA/ZUB2EAthOG/LsAwXFLfxPhABPMAgLE7N2Vnb2/9n1bEnvjzAozAYV+ACO/O0Yn/5SR/GoCJ3xlQtvopduexdednjGh8cGhw5O2p7NdOwuzD/jQa+I0k7AEMCXdKf1PP1e2X+ibwQ+O/PWd4oBmDSRgA2roItP1zAAz8u62zUT//pM+6egh+HuZE04enyeSLnHOGH70hZm6nbr8E7D8BAJLlYDUuCdaLfyg6fQ8GYeKBfuMl/UF0uLEH67YTFhYWKwI2BhG+2dRGmHiJNW5Ph3T9Rxj2/wLABrG3/R1DozQh0fsa0P5tkWVqhdDZ95M+o1AfCsMj9E9BopiYoaGw5QuMUdN46WphEwTtg1PrTrFvb4qAYez/pwHstfy0U8D0aMX7kj344r7FCrEVue093fq0bP3+O1fvXLrKshMnWIgLE9747OOu0/Ev+7O39xzadHCwFzhWxv7AAKMTV72ZMwaMsbZns6kxzYCN9E+iz8UEwgpCGaNV3/ew1vG88vLvAezEDAniwpZsyN1n5HkRfvm1sXrku6u+U9uzYbDr6X+UHO+hkvcAGIZwdf2OUfSsJmg8FghU5MhI+pdl9WwothBbVjTcrK+1UWujta21zYVvvhJDjXAFTi9bJrJMJL2wiNkE357SL9ly+Drkb/e9BFCY3Y39Lp7NI8Do5B0NXw1fGMXGHqEYeWqQ2oa+vXY2SCgIWrsuHE/svHlMK9hP4zMra2tbq2PUxEiHI0nxZJEVBILIsn2RVtZOJ6pqveP8gp0utkXob6cONH/5xYw7Y3C+cQKbd4BhiNgccmpzOIaHmUe9pyCz6SLZztLIzlAtM7/h7PGcBMMV67z9tgyXONrafuyATqqvZxZ9JSKCzGuZXZSztbVj5DG/FL/PTx5/UQ/VtKbzTBZH6kGUAcNnXUHNGmAUOrbqZ4arH5yGa1XfAoTkBu1VE7WwJAcZraDUnYg+GRUVeVNfS0ursL/U0fpjm+bBu2VlDfCN57IVIssIdV+Vl5ee89Ty8zMIPpk6473dBY248bDh6maDzbUTo/MMgBSgvjVE3/f7Nidrx+jcwNCjqmpqIoZkMtlQVC3pSGp09MlU8gaCHeFY/diNnBN1M1eNt95PsjQiX4OpK7en4OvTfnFbgk8mlyclFQVkPgR4hgGGtenrh+CxdZ4BRuDYps3h3ijAS1g5RhGEQr1UVVVFyfEONkY65oXFJ6OjU0+eO3j6Xgj0c84/lX2roZ3dC+dRgQfpVUckJMi5zEKDFIO4kzkOEh+ryYem5feh/u+HY+qHY/U1Omfpyu/hxFCrcexgBBZptdH5ZILQ4sWqoqo7QoL2WVgSTak3ElKjkxOA1g3VfZ0PHr4C+Lq1p6d/vL2/LHy4k3U/6mMrcbsa2jF1gy0nis/bfWq9Xj40VO9oZiuKZAxfjUDfzdmzVMF7AEzc0fDWioAT1tbOJ1NVhYRWiKqq7Yu3I8erCu19lpOQnFDOhv5OzrkvbpeWtHAKJiRhz72fix2trMSOA5SFRBAcLkKxE+EjWUE91LzybwFcR9FN3ffX0XnXwB0N/U3hd0utbR2TU/ctFhISFVU1QpEy3sEypAe7VnJzemigb5p1Nfe43UZxcWGJqoEHAxirqZPOguKPJSQcWjB2Y5GDhLjYxV9v6MrKKeht09l+wD+UyijbbKCR3YZNzC8AGzchb63whvJIK1vnBOZyXAWi4laR8UnXWPC2wqz6VEL4dfv8daWNXLkvySnjPoxjcETC2loscSJzubzcNtNtysZHQ0NN9Xy2GGjcgfmNQgO0XgzaNPS3eDMZ5U6ROZNwUEhxr6eimmduBzrch5/jQWHmxjqulfkbLv3fVn4SHBuby+j7V6IdH4d7VlbWG8VLIFBBVt7UVHf3F2fCwg6Yhm/x3VLbPp8AWH9hff+j6TINjS1aXx13tM3pot7LVduxI+hsDTr6cAzFKObZwI+WKy4X+kRGZuXKT/bbf2a3b+96/qWyyh7UaoCxwZGhcaSBBzYSGyWSgGF6yERTT0835ExYaOg2UriWvsbVwglsVtXd7DTQ3UwvBEbhVnV1/UhbW1vrXFQ8e8TQ0AP78S6mBaosX7JYTnY5v87pEyeiyfvU1qMotXgpPy8PH7+cG+2H1wO0Mbh25EgxsBsoB7yOHvA6GBOWlWaqF+Stpb85HR4NzaMGcCNhpIVt1VBfp2bnbHUEqrs49t2LBr3MECWBBcvlPlrKx8PDK7BcQXn9Yrzx8QnIabuHxMaGxKRRGb1v79U6/RJVgPXUo6YHQ9LCsrw03TOECVpb6OiMLvrPk/MBgI3hW9oB09CtBgbqevJGji2XDzWy+ziGn26moBNAOV9QWJBJJXnoLOHBZeflE9RxC8mkMZmNBbGkWEoIldHNhmk2G4ZGGCjQYijkt1EPeoadCT3gT84xEBbewrpZlGgplPvuA2ae2XT/7dvVads0NcMNDMI0TA8l3bhE7cfN9VZBiJIcKbO+8BSVSs1vBPbX+QWBcryyOj5pmZmVtZUI4DKdQiKRvAIoRbf6fls3YwO9Xaz8sDR/2aM37DT8CAQjCyNLS9Edfew5B8DgZqSFhYWCkpKivsFWA/3LLb9ANS499ZCKwBJSO7Q1MEbgPKqtWZ10Grykm8k1fF1ZkVVRSa+k0xvoBbGxPnokKqmg+m4h/bcM3UgVdJJeATPGa4eaqoihHTnIcAUFHs8xAIa1OIhv3ChhpKmpuV1DQ10fjWDGUXAPUVy6XFYwBppYQGt60NnA6O3vYjLh68rar4lKtRVnsipqayuzaNBEz4yNJZEyMwOo9ADefKz/X7fuo2Wiv2VC/qGK6zeI2MU72BkpEZvfdcT/rgBDkCRhYWMtYaGopLd9s/rhU+cfj6FyjcKzUBAREBkI8YdvuuAZ9PX3Mmru1tZmnakwJt4Jq6isRGqohOHG2uqC/MzYAgqJyog5izLKwBsJH3Sn+z+A0b28i9eLbNANIltaWhorBb6rF7yzCT1zsLKw3ihho7htj1FEBOP81QejSC1uC5fw8fLw8plQ6Kzay7U1zNb2F9/Sq6fvVCKCywqkiopa2uWKisvtcKfiMu0yHbk4hZLObO5se/0ajNN6w1ufAX2x0PoN6zYYocI83miFbuM7VqXvCjD5wuZjKysJK7K5p93pGtpVCEcRG1rKzeUUZAUFUOTkV3ZLo9Vcr2+AfnpjbWVl7Z2KynzBLypr6ZcvV16+/HVtZe3lgvz8/MzM/PNl5z0UD6U3oNv2D/z6+gH9cHDxOnX1DYRPI8nxOUXX2XPsA2y4IPHxRptUT/IR8jNaGVwKb/x5bKIlXkVHGW8KsgIo+i9SPkSh9cKdOxUVlbU//vgjUARpFVlZFZeRHVXSC2h0Rm11dUHsAYWPBJYsX6rgwhlNIzVM4OYyTl+3bpPGJjVDmxKOzQ7MrQZQCi1NulD8eV6xoV0RSkO+dwAbglwVXWNlFJiUjYnm8rJLEQSPoI4HJb+yoiLTR1n7y5dEpYpQvbAsOo1Gr/66tYFGPWQst4hP4CNBQQW55Uv45HwKfgWOtY94XmvcpL7BQEPXyDIo99rDeUhkKNmWGNq1/EPMsrcb+8IXPXYAcnV1VRTlFJSUzd3dzLSVlRTkBJFP8AoqHTiqzSfAJ9/aIOteW1HBbGquYeaHEJUEF/AvFJSVXSKwaMny5XJycoI8PNqUTs6rSUbbMXX1devU16mqrjC03Bcfc7b1nQLRu2vgFZZkY3e93Crq+MOf2YHnUcU1AJTdOxRVdpsr6xibmRmbmBjraCNrUtIWXMgnSKXR0tNbIVPAhUqlBLgqy/Hx8C1YtFRw6dJFSwR4eZGueBcsXLiQn4dH+SzyVwwaGUXqyAnUN6iq2QUFWRq9Yzp+ZwD2y0SbhPvg4Jx6MucWVLdz/GKviu7u3LbrscYmZubm5mZmZibGxkQ3V2OkCjltc59MikuA/IKli3h4efmR7IsWLhRADWlhAT8fH87Az8+LdgRCUHGBersMAWzasGFHUDw5EiWzuQUYghKn4l8AnD87kkSmFrx27BAV3XSor++imhGJu3cjBBNzM/O9rkRjHWMdHWLIIfmlgoKLlsrKygouXbRAYCESnLNZuGQJ6nyBBXz8Sxby8y9YyJePDQCbXbNBa5OWqIhaED7AFp1jgFetieT8AmrMwYMkkr8scYDNeROVvntvfdut1qb2GLM9e/bu3buHuGePuYkZMiZjMxcfH6KxtrKsrJwswhBcuoCXl3cBP2qIQYCji4VLFiIqgaWyCwM4sww1WlqbvdVWiH0WH+Rgaao9lwDo5kpeWf6aepqoFg31lw9gP+JMbZzV/Xs78kHkom57XFxcXd3QxsWcY03mRBeXXWYmATGuOihTIBWgJrBgAW48/AKchqMsRUcW8vEEMFFShAbfEwZ+ZDtLCydyvKWiwlwCDEDBIj1/Pc1tmttIoWFHlSiv57vo5oEsVnsXq+YxxRyJ7+7u5oZDuOzZQyS6uBLNTLTdM2tiUGzC29JFyIEFFi1axBF/gQASXnYRH88SJVeSqzuyICgL7NiSV3ojxyHnYk6S5Zw6MSp6+JcLIPkVA74khR7QTPMtxMMqBunuDe0NXb1tvXQXVzc3dw+8uXGaK+IgEneZ6CAz0tZWQgyyyJT4Uc7GGy8yHEF+Hl5ZY1Ja/p0f3ZR7kLTnj9F170BJdGo5FE2z6A2AzaEGDvHLyuvp6RyknDkTpqm3Sd2gBxvHCfIZ/b2tDc13ewJczE1MzPe6efj4eHi4c3Th6ooQ0LcB+fTzAcpyCvKkkJCAAHeiGUrcC5bw8OkEnGcyq2mNVyvMFQrQWC89/NamRoi0SU26HcGa20SGYWZLEMA2FU80+jvqpb/Z4F9v0L7trGd13oJYVw9XMxVlFZM9ru4+HAiOFpAdxaCan9WeaaKktIvqQ0qjZqJhT2a+jjGt9wW6nHXvwZ2jQrsbUWWV7Xtaq/talPPJaHozDLHnsJTAoFlhyRL5baa7/54WdsZLc7Oft7rBo9EJbAL5QVNr761bTZDu6nOIFOBBNFZR0jZz4SjCHRG4mrt39TS0Nja0F6CiwyUgrYBWkJmZSXWXzYTevlGs/xGT6qONgjF7AE75HvN+dsE5+KSF5wVgj8+hBthAU96l7Wp64GAgKeyM/7rNfnHeb1XQx+juamABIyAgwMftEIkU4G6uo6JtQnT1QAiu7mYUaII+FqvxLkXbWNlkF9HFREFBQXChMg1d21xA8TFRMTFTLsRnMem++t5Xkv7hZyEsJhYPI+NzB4Bqhm0HXAK8Dhz0DCD93eiYn4af3+atnVgj5w1oJ7OhBg10+7r7mZmxAR4+AQEIYpeONkoF7u4exAL23W4Yaettq/YxRmFJWVnbGDUzE7MQSgARP8vE+JAHkQljnc0Np8UIBMJnhsJiBLFEGJk7gJ+BRj1PY9R0Pe0qIjtbn8zY6uenrn4JTl3C3ytAb3Pv2zHudE1+bICPTwDShBtKaUQPF9pAfzur4W5rU2+6CUoQ2rKyCsrGKE0g70Ypz9jMLQbpwi0T3aGvzVBczFBMwgYBiBOuvxvBLF8t9teQrfZbxyEAg6sDXY+x307MoYps4ClnpyafQkIQuE25udDYzV1NvezO9mfVLkhu40MUSoCbj7srCrEmxAAKHQX73ut0FtxqhjpDcUMLsY3RSA+GyIgG5xCAPTDAfoSVpQ/ln7WIcvzUYKuBX1tnZy80dwI2+W/xGmPPjKVqCnAInwDXAmDdbe9t6mINPCOZu+AxCbCYQz4uJj6UgkbcPhuYNe04dU97Tw4SXcwx1cLQUEzcbh400HMH7pxNSjq5UX2/hkFDNRK8lXELfr/mAWNzNAENhRSSKxVF+HZWX2tNN1DMXYjMnmagEVFEisUv62lkMhu60U57fjOj8GvIkSCIWRXnIEUggKF5MCEoT0h2dshYp7XFAOhMvOt/+Jb9X1euYGxOIdDHpA90Pu3rau3qGYB8IhEVIZCPBg7KVGB3NtbUcKRHsTituiwxMjGm9aR1Th3cTzUUE8udB4Ax7EZC9JEopwu+m4U3FwHzLgYXyRZGp9ndz97MsvdP/N6c+rqQ71Qjc6ERzQ5RPHRQGSfoWsC42941MJMl4ZIvEy7aWKwQsrSxfArV2a+qzl2EOQyj/xoX50RFJyR/etrXT0NrXSAqkZLExcTFVhQNDL4WuPD8o/9IoCi+Y/Xt0NPLegENpJAAn0MBIRRqQcMt/NXb5Ix/MXzvDOWSLch2hqKEOoCIS7OYtp8NAAa3E6ITEqKjIH2rn8HGZafGcsXELSzEhRORch5lX4XRCY5X/v7KZkZNQxdub//2LRrPdzc8Q8prLYwnGDoYWVparFC7MZkdDuxXgyMw9wBjcC06KiE5Oqf+fPjhzcF2RWCJvA2Za0lv86MHWhHYcOev6dn/dXqivaZrZmdi+CdqK7uPzRmw9zF6UQa5ddZTTUTNxpAcH2QkuiIRy27um8VE5ew0UJ+QnJyc2lITmH5L3TsnscxSTMJQTPg4sJiNP7Qi63/JulQLPcPs4eFnqA38MPA7bTyCiHX6ffhKkZ+/QaLDi0wSUY0zVW5JRsMYw2W78ZMG5gcAxh8nJUcnJ11/kUv5Vouaa2FjIy4ubpNzHz/WVt3QfOt2PaOhi/FfEwn2eorzqnq2rzeMsr/tpDLGgKLinxW6XkVNZAUhkRxvQxbapV0w2j9vMzSTcK845waL1txcX7Q9MdrZ1tHRpjjpFjyuuzkFJHlNr6P+pl4+PiQSKa0gP7Mgk5qZ2QdjQ2/D4dhPYw+2hAPoH3uKeH6EoQG3xT5hpoqKqqpqnolBQRYWOw74u85uAdR7rBd6WtYGfezTjo621laOthe+Coq3JBAsLwbIy2dlZemZooY2aOSc5rVIU6l95LXx3ZpJrIfVL/Vla226252bU3ztBTCEhBYvXq8qKqK7lxyzL8hin4IyX+6s1jPOEmB8BBsE+jE0XsIX0zg7O9pG3s8VXrFCTJigKy/vHxqqp6lnukvz6G7TsDCvUHnNXdNw88KF/gEIRCVE/5XSC5s2+bK9vZtvk52ioiKLn4EPr9ByIVEREcUd+GR/EnmHkOqOzrH51QBAfWHTZIKzra0tgjgCQcIiBIK42HrB5QsFZPX0tmmrKB0wC/UP8wrTVCK2JDnZGF4DFsq49edSU1NOHPYF7whIdI52OnIkugpyFwsJLRERFV2vauSQRE6MJ1vujWmbzXLG9wHAoK/6cSTq/ShkRtEjdsIEgoXYx+vRqF1WQW/bNmVNFaXQL0lo8IwG0U7WNjZJD4FZAP3HU1OTUzP8DkNgRPmRaMcjKKGkxhbsRQRCoqgZfpoQHxkZ/1XTPC+3eZMkk2yjrK0dnW1z4PQyAkFEzFYRyY8P/PV0tqkEZeFT116meipOjpHFyHvbAFqSUxMSEIDv977UYudo56gj0dGR8eVkJL/QelFREcJGC4f4iy9hlit633PZ5ch4nY1zlLOzbfTDsiq7ZSIEcQtFWTk5BKBraq77d0paVlhaqNc2PZ2E4hY0yoGy68yS5NTk6JQMPy3PTdQbUclR0cnR0cnHvf02IBWs37dXUXGHZxEKdGwMPgQAysqlDsgJElrgdNEvxw0JFknKsh/NaMBMNzD2izNnsrK2ycu6foe/eGhtb00vzE0+mXoyOcVPK0jLM9ExOSHKOSr5Hwa+pwsVVXccDNq3J4b5Zir6gwAgM3pUWlLFWTswCt+1/PJMaTkCUNLT1dPVDQoJDcvKOiPv72+eS6u5WX+LmWiXdP1GFCKI208gCHvmJkQlo5R45HT2je8hRm2v4g5qM1Lr+6yAff+105ywzh4vrEU6fwFwXVlO7qPl8prb9LbreoaEhYWdCdMM9d+dRCbbWNk4WVtbOyVVJUQn5x0meG85XXMxISoq6siFZ/3wkt2gsofK4kw1wQcFgMmRIaTxbx7B1UuTj8bpih4HidsOeOn5BwYGxuDyh8rpaZK+qyt2lrC2stpoZWV7YfrGxUJffQP1U4yG6tKcC/UzgwGoxt5b/LlYfo+GI9moRivQ9Pfy8iGl7Tqw9yDygbCsM2k6CrJpUDZV4ogA8Jzn1IGGPRHp2ZtqgFXzDb7gowda++CPiD9nP0FhA83V64COiauP6y4zs927/VFSDvM6oBcz+T27BQFYc5LehfqYmB0xXx2swfv98XdNjH5ohT/4i625AJjgDCN/udd+t7m5uaGaQS8spNNptIK0L9Myoa/1Jh6unJD8tknXc786RaWewqAm8zqTwYCedlZb7x97+Af4KeIPTrbO1ihnO9qWcl7kDb9kY6wmBi2ksK26949Yz1wDYK8bm9OG2W3Z4QaXgP0QkqycHS2sHW0dOkaGRtAwOL8ZmVxvP8zJr2jmTwMT/dlbtyKASazDycoxytnWpuQ/XlX9GX5D879b79OZdxkdx22sbRy+grH/fHn0JwcYffs2Bm5fq5qGsfl4yLxq4E1dPz7yNnX/tQB+gzI2Nk935v6imwvABeACcAG4AFwALgAXgAvABeACcAG4AFwALgAX4IMBTE7if+a+jX8YgMHxPyrn+P9ZA9NTU9PPns79f4T38umzyfkHGJ/O2C8jE7dzZykMTeJvPTndOT4y8nymXyfR/vOZndcXPB95vQoanfQK7T1saeNc+QpdM/n2zMlByJDZf3/2ZjRLgCEolZLaH5yycmUevioSF/X5m2PP325/JwWim5w5PAh5a3dWvb3o+YztI6t6BXGSMvMP8GQqY5VMx/Q3paUd8PLFFLSUtqBnTrdUXbnC+Q8wpp5N/3qlasbO8AbTHTOHUDffvHKl7v5PU3lSq6umfoaHdegjEv7RwBTCmJp6ADdLrozOtwk9gbg1q1fLyMjs/6QUqdw+bo20zDmAjJUrV66SiXsFVZ8g65JaE/UY4mTw9klH6RqplSvXBj949TBqzcqVUjunUtbiN4ib2r9q5UrpT0rg5n6ZFGjZLxOH3+/BfGvgDcBa6VV5SOXSa+1lpGQ6ICM4ryRlNfqqVEpa2n6/tBQ6uFZGZrXUmo7S4LzSDBnJODgnKZOXF2fPTsFvsDYO+zwuL89ecie6WHJNebTkzpYPZEIvUlbJ3PyhZPVqJKMU2mRIrS4HqMvLSJFZFQWla6SjoE5mVQo87Jk6t2Z1BkALOrRzlT2kIICqpzD6Ik96TfkPj2CqNCMlavXqUoDoVTKr16KboDvPP8Ag/pgWKJGWxjWws2MwTxrJkLJScuXK1VLBCEAq73mHzKo4eAh5a6SQ/OfW4Iek90PVTklJZEv3IU9qLXLilv2rJFdKr5YuRX3yiTQ68+EH0gAOcHO8RHr1DAASZ3X5/bVSUXVdOyWjOADQgVsMkn8Nkn/qE0n7Kpa9pD1SRUrw/tWSGfgVyHkzVq0918Ghh3IZaangXz8cgBSugdVrSiBuFQ4gvbqqY610ChIYWU/5GmkcAGkgb610VN2Vqv6dq4KRhFL2UFc+Pd0iI5mCX5Fx5R4KZnUQjAM8QIz49x/GhBCA5JqbUCK56o0GJKVKIVhSSkZmjSQyISlJBLAWaWC/pDQKPytbUiSlkDtL7oeMv62VWbtKpmq8bu0qqb9ltKyVXLNTRloybxB58uNzqzj3k7n3ARJZiX1wB1wLDr4CF+w/74Fy++A6uJ8SHFd1wj4D6oLtr8D9z+3z4EQwp7WgCBVcmmF/Aurigu2D4+pQzC9F3+dBeXRwypXg4Lo6dBzghP2J6Tz7zx/OO8AcVJzjv688x/9AbTtrgPEng/jmCUr+g2/20ObJ86Enz2F8EH2CwSevYOgJ3gbxD0+eP38yhB9C7RVePnD+RdvBV/jF+Nlo8xxePRn8EADcERkXgAvABeACcAG4AFwALgAXgAvABeACcAG4AFwALgAXgAvABeACcAG4AFwALgAX4C/e/glFel/ClUOL7wAAAABJRU5ErkJggg==",
  "/icon-512.png": "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",
};

// Se decodifican una sola vez y se guardan, para no gastar tiempo de cálculo en cada petición.
const iconosListos = {};
function icono(ruta) {
  iconosListos[ruta] ??= Uint8Array.from(atob(ICONOS[ruta]), (c) => c.charCodeAt(0));
  const bytes = iconosListos[ruta];
  return new Response(bytes, { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
}

/* ---------- Entrada del Worker ---------- */


const RUTAS_API = ["/api/movimientos", "/api/jornadas", "/api/me-tienes", "/api/pagos"];
const IDENTITY = "/.netlify/identity";

export default {
  async fetch(req, env) {
    const ruta = new URL(req.url).pathname.replace(/\/+$/, "");
    const esIdentidad = ruta.startsWith(IDENTITY);
    const esAdmin = ruta === RUTA_ADMIN;
    if (ruta in ICONOS && (req.method === "GET" || req.method === "HEAD")) return icono(ruta);
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
