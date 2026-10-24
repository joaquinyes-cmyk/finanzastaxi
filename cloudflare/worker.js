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
  "/favicon-48.png": "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAD40lEQVR4nO2Xa2hTZxjH/0nanl7Si6WrsnW4je1LpxPGRpU5ZINNkN3tmGwMrGNR2JA59YOiVVtBwYoX/GK84x0VClpBRUGpaAXvN0RQRP1glbbm1iRtcvw/ObaJkrYnOYlH4fwgL09ODjnv733f53nfY6uoqFDxBmMJmI0lYDaWgNlYAmZjCZiNJWA2lsBAjB3VwzbO2Wu5bDNPVgQ2zPPi25oQozhH2xT8vayYUWbJisDepU+TzsBvC0oZZZaMCbxbGcU7lRFGQGWZigmfhjHmo15+Ay7fzsHJC3lo77LxG/Cw3YH77XZGxsmIwK9fh9A008tIP65lJTjSlsfIGBkRaHV3sgXmrnWyjTOZYsKBEwrbOCtm+tgC413D2BrDsMDEmjDc8zyYvbYY+1/q6H9TAmyB1XsK2cappdhKztgU5sQZ5oYRDAvsYcJWcf0nG82BBASZtZt3cwxXJkMCkrit7g6sYgeTdXIwAfltFj/jXeWGEtqQwEqu5W+4hGT0PX6twiQinRSSCZQUqZTvjOXHkk1FvJIeugVktGtY26uel0qFS3fa992MgMddyUdQOikkkxPeKouyBTYfLEDo+bbxgCW2jXmhd1Z0CYxjx9dzdy0t0h6YbZ767ZjO3NCT4LoEDq/qwsfva5vSq+I6E3zSrDJGg6NL4F7zE7Yasp5lKcmsZCNOZORPFWwHJ2UB+VNJTqkg2YgTketDkbKA0Fc25Xo24j6yJiDJdeycwqNCEB6fLXbSlNGT66nGh04rmPFzN6uPvf96HxkTuLqzgyVRq0BSIZp2FGLi2DCUPBVXbueianiERwrt3KOXI3w/uM+SOebDHgSCNhzjwW7un4H+Sufhc0b/Uc5ocHQJLPrL31/z691OfPFJD+o3FMEbsKHuuyAK8lX8+GWIe4W2RwyFdLylVUEXO7mtReHgqGhw+dF6MReNM3y8Q9sb9GxwugTkATK140b38kxvx5KNhQiHbahmaZUj8bZ6Dzq8dvwyIci7h6b5ZD5KnCrqGos5c2HcYMnMV1QsqAtgeHkUZ67mxHJioA0wEV0Ciexu9OD/NU68NyISe+uSB62b48OWlgKcv+ngHUPzWXUEUyd1498mZ2xgZO3fe+TgO4UPvy8s4R36SVlg2g9BjBwRxSK3dr75vLoX/9R2Y2qD/lOljQO7fbEXTbsKcemWJt0w3Y87DxzY2pLPb/pJWUCY/FUItfx0+uzIdahwLS+GmuK/iMTG+d7YGaiUS3TfcQXNp158n9BDWgLC25UqhjmjuH5HG8F0GfVBJDYQD9tplAZpC7wuWAJmYwmYjSVgNpaA2bzxAs8ArO/+UHpmm8MAAAAASUVORK5CYII=",
  "/icon-192.png": "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",
  "/icon-512.png": "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAgEElEQVR4nO3dT6xcxZ0v8BMDsRObfwlilShi+QKZLUSPFdIDDU9IkQYUIlYTK54diQWzQCJEASQWA3LCbhyZWaEQwUiR0GMET/KKp+DtBHhLKyIrlOG/M5AMZOp3L5e0ja/d3XVuV53z+3ykts9FxnW6Xaf6W3WqTn3hmmuu+csAAKQiAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAACQkAABAQgIAdOrbN/x5+LtbPhq+ed1/DdeX15S8dvrS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qr2iED2jf3js8o0Pj8Yw6D+VYdxle0JBb4hF6jtZCQCcV2xgsuwuZovuLz2jZ0/uL0d77/t3fDj8ZIUJUDum9HhXNkN9JyMBgF0t+7S0c8WSqUdOHNyz2cYxe/vH5dyWXfq0yFAou1HfyUYA4IKW3V70fJ49eWB4uDSMYw09xlBtbKt61wqztheZBc3FqO9kIgBwQdEI/erRd5faOOV84l5pbHm681pHbKG681rl3uei2ADluw9eOVrjzDyp72QiAHBRMQT5wrF3SuO4XmO0KIZLXz99yfDKp5On3i8N5s5s6pjdfPmnZdx0w59LI/zxWsOe54pJULcfvWrPhmiZF/WdLAQAlhKN1TOlZzRGo7hJ0RjGw1t2Gl1YhvpOBgIAS4ueUTx5bN3h0U0zDEoN9Z25EwBYSdwjjcenrjtRalNiAlTsea4xpIb6zpwJAKxl3SVTm2DpE2NT35kjAYC1xcNTYplSL/dJ4/7n/U8eGjz0hL2gvjM3AgBVYoj0cOkZxVPKWjWM0RA+9fyB4cTzXyrHhkDZO+o7cyIAMIpoGGOYdJWtVcfg3ictqO/MgQDAqGLmdOysFg8x2aseUvSA4iErce/TWmdaUt+ZMgGAPRNrqaOHtP2Qk7qlVLHEKR6mEj0ga5zpkfrO1AgAbET0lBZ7SdFIhhhK3Wkso9HbGdqMxi/s9H70fJgS9Z0pEAAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAICEBAAASEgAAIKH/BvhMOzw8PyT2AAAAAElFTkSuQmCC",
};

function icono(ruta) {
  const bytes = Uint8Array.from(atob(ICONOS[ruta]), (c) => c.charCodeAt(0));
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
