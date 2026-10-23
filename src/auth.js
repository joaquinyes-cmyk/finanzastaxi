// Cliente mínimo de Netlify Identity (GoTrue).
// La sesión se guarda en localStorage y la llave se envía en el encabezado
// Authorization, así que no depende de cookies (que muchos móviles, navegadores
// integrados y vistas previas en iframe bloquean y hacían que la app se cerrara sola).

const BASE = "/.netlify/identity";
const CLAVE = "finanzastaxi.sesion";
const MARGEN_S = 120;

export class AuthError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

const ahora = () => Math.floor(Date.now() / 1000);
const oyentes = new Set();
let sesion = leerSesion();
let renovacion = null;

function leerSesion() {
  try {
    const s = JSON.parse(localStorage.getItem(CLAVE) || "null");
    if (s?.refresh_token) return s;
  } catch {}
  // Sesiones creadas por la versión anterior de la app (librería de Identity).
  try {
    const viejo = JSON.parse(localStorage.getItem("gotrue.user") || "null");
    const t = viejo?.token;
    if (t?.refresh_token) {
      const expira = t.expires_at > 1e12 ? Math.floor(t.expires_at / 1000) : t.expires_at || 0;
      return { access_token: t.access_token, refresh_token: t.refresh_token, expires_at: expira, user: viejo };
    }
  } catch {}
  return null;
}

function guardar(s) {
  sesion = s;
  try {
    if (s) localStorage.setItem(CLAVE, JSON.stringify(s));
    else localStorage.removeItem(CLAVE);
    localStorage.removeItem("gotrue.user");
  } catch {}
}

async function pedir(ruta, { metodo = "GET", json, form, token } = {}) {
  const headers = {};
  let body;
  if (json) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  if (form) { headers["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(form).toString(); }
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    // "same-origin" envía la cookie de la protección de acceso del sitio; sin ella
    // Netlify bloquea la petición y parecía que la contraseña era incorrecta.
    res = await fetch(BASE + ruta, { method: metodo, headers, body, cache: "no-store", credentials: "same-origin", signal: AbortSignal.timeout(15000) });
  } catch {
    throw new AuthError("Sin conexión. Revisa tu internet e inténtalo de nuevo.", 0);
  }
  const esJson = (res.headers.get("content-type") || "").includes("json");
  if (!esJson && !res.ok) {
    // Respuesta que no viene de Identity (p. ej. la protección de acceso del sitio).
    throw new AuthError("El sitio bloqueó la petición. Recarga la página e inténtalo de nuevo.", 503);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new AuthError(data.error_description || data.msg || data.error || `Error ${res.status}`, res.status);
  return data;
}

// Datos básicos del usuario guardados dentro de la llave (JWT), por si /user falla.
function usuarioDeLlave(token) {
  try {
    const p = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { id: p.sub, email: p.email, app_metadata: p.app_metadata || {}, user_metadata: p.user_metadata || {} };
  } catch {
    return null;
  }
}

async function abrirSesion(tokens) {
  if (!tokens?.access_token) throw new AuthError("No se pudo iniciar sesión. Inténtalo de nuevo.", 500);
  let user;
  try {
    user = await pedir("/user", { token: tokens.access_token });
  } catch (err) {
    // Las credenciales ya fueron aceptadas: no se muestra como contraseña incorrecta.
    user = usuarioDeLlave(tokens.access_token);
    if (!user) throw err.status === 0 ? err : new AuthError("No se pudo cargar tu cuenta. Inténtalo de nuevo.", 500);
  }
  const s = {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: ahora() + (Number(tokens.expires_in) || 3600),
    user,
  };
  guardar(s);
  return user;
}

export const usuarioGuardado = () => sesion?.user || null;

const normalizar = (email) => String(email || "").trim().toLowerCase();

export async function login(email, password) {
  email = normalizar(email);
  const tokens = await pedir("/token", { metodo: "POST", form: { grant_type: "password", username: email, password } });
  return abrirSesion(tokens);
}

export async function signup(email, password, data) {
  email = normalizar(email);
  const user = await pedir("/signup", { metodo: "POST", json: { email, password, data } });
  // "recovery_code" solo lo envía la versión de Cloudflare (código de recuperación sin correo).
  if (user.confirmed_at) return { user: await login(email, password), confirmado: true, codigo: user.recovery_code || null };
  return { user, confirmado: false, codigo: null };
}

export const recuperar = (email) => pedir("/recover", { metodo: "POST", json: { email: normalizar(email) } });

// Cambia la contraseña con el código de recuperación (versión de Cloudflare, sin correo).
// Entra a la cuenta y devuelve el código nuevo, porque el usado deja de valer.
export async function recuperarConCodigo(email, codigo, password) {
  const tokens = await pedir("/recover", { metodo: "POST", json: { email: normalizar(email), recovery_code: codigo, password } });
  return { user: await abrirSesion(tokens), codigo: tokens.recovery_code || null };
}

// Genera un código de recuperación nuevo para la cuenta con la sesión abierta.
export async function generarCodigo(password) {
  const token = await llave();
  const data = await pedir("/recovery-code", { metodo: "POST", json: { password }, token });
  return data.recovery_code;
}

export async function verificar(token, type) {
  const tokens = await pedir("/verify", { metodo: "POST", json: { token, type } });
  return abrirSesion(tokens);
}

export async function cambiarPassword(password) {
  const token = await llave();
  const user = await pedir("/user", { metodo: "PUT", json: { password }, token });
  if (sesion) guardar({ ...sesion, user });
  return user;
}

export async function logout() {
  const token = sesion?.access_token;
  guardar(null);
  avisar();
  if (token) pedir("/logout", { metodo: "POST", token }).catch(() => {});
}

// Devuelve una llave válida. Si la renovación es rechazada por Identity,
// la sesión deja de existir; si solo falla la conexión, se conserva.
export async function llave({ forzar = false } = {}) {
  if (!sesion) return null;
  if (!forzar && sesion.access_token && sesion.expires_at - ahora() > MARGEN_S) return sesion.access_token;
  if (!renovacion) {
    const refresh = sesion.refresh_token;
    renovacion = pedir("/token", { metodo: "POST", form: { grant_type: "refresh_token", refresh_token: refresh } })
      .then((t) => {
        guardar({ ...sesion, access_token: t.access_token, refresh_token: t.refresh_token || refresh, expires_at: ahora() + (Number(t.expires_in) || 3600) });
        return t.access_token;
      })
      .catch((err) => {
        if (err.status === 400 || err.status === 401) { guardar(null); avisar(); return null; }
        throw err;
      })
      .finally(() => { renovacion = null; });
  }
  return renovacion;
}

// Comprueba la sesión guardada al abrir la app.
export async function usuarioActual() {
  if (!sesion) return null;
  const token = await llave();
  if (!token) return null;
  try {
    const user = await pedir("/user", { token });
    guardar({ ...sesion, user });
    return user;
  } catch (err) {
    if (err.status === 401 || err.status === 403) {
      const nueva = await llave({ forzar: true });
      return nueva ? usuarioActual() : null;
    }
    return sesion?.user || null; // sin conexión: se usa la sesión guardada
  }
}

// Avisa cuando la sesión se cierra (también desde otra pestaña).
export function alCerrarSesion(fn) { oyentes.add(fn); }
function avisar() { for (const fn of oyentes) { try { fn(); } catch {} } }
window.addEventListener("storage", (e) => {
  if (e.key !== CLAVE) return;
  sesion = leerSesion();
  if (!sesion) avisar();
});

// Procesa los enlaces que llegan por correo (#confirmation_token=… o #recovery_token=…).
export async function procesarEnlace() {
  const hash = new URLSearchParams(location.hash.slice(1));
  const limpiar = () => history.replaceState(null, "", location.pathname + location.search);
  const conf = hash.get("confirmation_token");
  const rec = hash.get("recovery_token");
  if (hash.get("error_description")) { limpiar(); throw new AuthError(hash.get("error_description").replace(/\+/g, " "), 400); }
  if (!conf && !rec) return null;
  limpiar();
  if (conf) return { tipo: "confirmacion", user: await verificar(conf, "signup") };
  return { tipo: "recuperacion", user: await verificar(rec, "recovery") };
}
