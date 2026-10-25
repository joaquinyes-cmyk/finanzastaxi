import {
  AuthError,
  alCerrarSesion,
  cambiarPassword,
  generarCodigo,
  llave,
  login,
  logout,
  procesarEnlace,
  recuperar,
  recuperarConCodigo,
  signup,
  usuarioActual,
  usuarioGuardado,
} from "./auth.js";

const $ = (id) => document.getElementById(id);
const fmt = new Intl.NumberFormat("es", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const hoy = () => new Date().toLocaleDateString("en-CA");
const fechaInput = $("fecha");
const form = $("form-registro");
let tipoActual = null;
let resumen = null;
// Lo pendiente acumulado entre socios (todas las jornadas menos los abonos).
let pendientes = { teTengo: 0, meTienes: 0 };
let movimientosDia = [];
let jornadaActual = null;
let usuario = null;

/* ---------- Acceso (login / registro) ---------- */

const formAuth = $("form-auth");
const formNueva = $("form-nueva");
let modo = "login";

function avisarAuth(texto, tipo) { $("auth-mensaje").textContent = texto; $("auth-mensaje").className = tipo || ""; }

function mensajeError(err) {
  if (err instanceof AuthError) {
    const m = (err.message || "").toLowerCase();
    if (err.status === 0) return err.message;
    if (err.status === 404) return "El acceso con cuenta no está activado en este sitio.";
    if (m.includes("confirm")) return "Primero confirma tu correo: revisa tu bandeja de entrada.";
    if (m.includes("registered") || m.includes("already")) return "Ese correo ya tiene una cuenta. Entra con tu contraseña.";
    if (m.includes("expired") || m.includes("invalid") && m.includes("token")) return "El enlace ya no es válido. Pide uno nuevo.";
    if (err.status === 403) return "El registro de cuentas nuevas está desactivado.";
    if (err.status === 422) return "Revisa el correo y usa una contraseña de al menos 6 caracteres.";
    if (err.status === 401 || err.status === 400) return "Correo o contraseña incorrectos.";
    return err.message;
  }
  return "Algo salió mal. Inténtalo de nuevo.";
}

function cambiarModo(nuevo) {
  modo = nuevo;
  document.querySelectorAll(".pestana").forEach((p) => p.classList.toggle("activa", p.dataset.modo === nuevo));
  const registro = nuevo === "signup";
  $("auth-titulo").textContent = registro ? "Crear una cuenta nueva" : "Entrar a tu cuenta";
  $("auth-enviar").textContent = registro ? "Crear cuenta" : "Entrar";
  formAuth.password.autocomplete = registro ? "new-password" : "current-password";
  $("olvide").hidden = registro;
  $("campos-registro").hidden = !registro;
  formAuth.nombre.required = registro;
  formAuth.apellido.required = registro;
  avisarAuth("");
}
document.querySelectorAll(".pestana").forEach((p) => p.addEventListener("click", () => cambiarModo(p.dataset.modo)));

formAuth.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = formAuth.email.value.trim();
  const password = formAuth.password.value;
  const boton = $("auth-enviar");
  boton.disabled = true;
  try {
    if (modo === "signup") {
      const nombre = formAuth.nombre.value.trim();
      const apellido = formAuth.apellido.value.trim();
      const { user, confirmado, codigo } = await signup(email, password, {
        full_name: `${nombre} ${apellido}`,
        nombre,
        apellido,
      });
      if (confirmado) {
        mostrarApp(user);
        if (codigo) mostrarCodigo(codigo, "Tu cuenta está creada");
      } else {
        cambiarModo("login");
        formAuth.email.value = email;
        avisarAuth("📧 Te enviamos un correo. Abre el enlace para confirmar tu cuenta y luego entra.", "ok");
      }
    } else {
      mostrarApp(await login(email, password));
    }
  } catch (err) {
    avisarAuth(mensajeError(err), "error");
  } finally {
    boton.disabled = false;
  }
});

$("olvide").addEventListener("click", async () => {
  const email = formAuth.email.value.trim();
  if (!email) { avisarAuth("Escribe tu correo y vuelve a pulsar «¿Olvidaste tu contraseña?».", "error"); return; }
  try {
    await recuperar(email);
    avisarAuth("📧 Si el correo está registrado, recibirás un enlace para cambiar la contraseña.", "ok");
  } catch (err) {
    // 501: la versión de Cloudflare no envía correos y usa el código de recuperación.
    if (err instanceof AuthError && err.status === 501) { mostrarRecuperar(email); return; }
    avisarAuth(mensajeError(err), "error");
  }
});

/* ---------- Recuperar con código (versión de Cloudflare) ---------- */

const formRecuperar = $("form-recuperar");

function mostrarRecuperar(email) {
  formAuth.hidden = true;
  formNueva.hidden = true;
  formRecuperar.hidden = false;
  document.querySelector(".pestanas").hidden = true;
  formRecuperar.email.value = email || "";
  formRecuperar.codigo.value = "";
  formRecuperar.password.value = "";
  avisarAuth("");
}

$("recuperar-volver").addEventListener("click", () => mostrarAuth());

formRecuperar.addEventListener("submit", async (e) => {
  e.preventDefault();
  const boton = formRecuperar.querySelector("button[type=submit]");
  boton.disabled = true;
  try {
    const { user, codigo } = await recuperarConCodigo(formRecuperar.email.value, formRecuperar.codigo.value, formRecuperar.password.value);
    formRecuperar.reset();
    mostrarApp(user);
    if (codigo) mostrarCodigo(codigo, "Contraseña cambiada");
  } catch (err) {
    avisarAuth(err instanceof AuthError && err.status === 400 ? "El correo o el código de recuperación no son correctos." : mensajeError(err), "error");
  } finally {
    boton.disabled = false;
  }
});

/* ---------- Código de recuperación: verlo o generar uno nuevo ---------- */

function mostrarCodigo(codigo, titulo) {
  $("form-codigo").hidden = true;
  $("codigo-resultado").hidden = false;
  $("codigo-titulo").textContent = titulo || "Guarda tu código";
  $("codigo-valor").textContent = codigo;
  $("codigo-copiado").textContent = "";
  if (!$("dlg-codigo").open) $("dlg-codigo").showModal();
}

$("codigo-recuperacion").addEventListener("click", () => {
  $("form-codigo").hidden = false;
  $("form-codigo").reset();
  $("codigo-resultado").hidden = true;
  $("codigo-error").textContent = "";
  $("dlg-codigo").showModal();
});

$("form-codigo").addEventListener("submit", async (e) => {
  e.preventDefault();
  const boton = $("form-codigo").querySelector("button[type=submit]");
  boton.disabled = true;
  try {
    mostrarCodigo(await generarCodigo($("form-codigo").password.value), "Tu código nuevo");
    $("form-codigo").reset();
  } catch (err) {
    $("codigo-error").textContent = err instanceof AuthError && err.status === 403 ? "Contraseña incorrecta." : mensajeError(err);
  } finally {
    boton.disabled = false;
  }
});

$("codigo-copiar").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("codigo-valor").textContent);
    $("codigo-copiado").textContent = "Copiado.";
  } catch {
    $("codigo-copiado").textContent = "No se pudo copiar. Anótalo a mano.";
  }
});

formNueva.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const user = await cambiarPassword(formNueva.password.value);
    formNueva.reset();
    mostrarApp(user);
  } catch (err) {
    avisarAuth(mensajeError(err), "error");
  }
});

/* ---------- Ayuda ---------- */

document.querySelectorAll("[data-ayuda]").forEach((b) => b.addEventListener("click", () => {
  $("dlg-ayuda").showModal();
}));

$("salir").addEventListener("click", async () => {
  await logout();
});

function mostrarAuth() {
  $("app").hidden = true;
  fechaInput.hidden = true;
  $("auth").hidden = false;
  formAuth.hidden = false;
  formNueva.hidden = true;
  formRecuperar.hidden = true;
  document.querySelector(".pestanas").hidden = false;
  formAuth.password.value = "";
}

function mostrarApp(user) {
  $("auth").hidden = true;
  $("app").hidden = false;
  fechaInput.hidden = false;
  usuario = user;
  // El botón del código de recuperación solo existe en la versión de Cloudflare.
  $("codigo-recuperacion").hidden = !user.app_metadata?.codigo_recuperacion;
  const nombreCompleto = user.user_metadata?.full_name || "";
  $("usuario-email").textContent = nombreCompleto ? `${nombreCompleto} · ${user.email || ""}` : user.email || "";
  avisarAuth("");
  cargar();
}

alCerrarSesion(() => {
  usuario = null;
  resumen = null;
  movimientosDia = [];
  mostrarAuth();
});

/* ---------- Copia de seguridad en el móvil ---------- */

$("descargar").addEventListener("click", async () => {
  try {
    const res = await api("/api/movimientos?todo=1");
    const { movimientos } = await res.json();
    const celda = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const filas = [["Fecha", "Tipo", "Monto", "Nota"], ...movimientos.map((m) => [m.fecha, m.tipo, m.monto, m.nota])];
    const csv = "﻿" + filas.map((f) => f.map(celda).join(";")).join("\r\n");
    const enlace = document.createElement("a");
    enlace.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    enlace.download = `finanzas-taxi-${hoy()}.csv`;
    enlace.click();
    URL.revokeObjectURL(enlace.href);
  } catch (err) {
    if (err.message !== "sesion") avisar("No se pudo descargar la copia", "error");
  }
});

/* ---------- Panel de movimientos ---------- */

// Llama a la API con la llave de la sesión. Solo vuelve a la pantalla de acceso
// si Identity confirma que la sesión ya no es válida; un fallo de red o del
// servidor no cierra la sesión.
async function api(url, opciones = {}) {
  const llamar = async (forzar) => {
    const token = await llave({ forzar });
    if (!token) return null;
    const headers = new Headers(opciones.headers);
    headers.set("Authorization", `Bearer ${token}`);
    return fetch(url, { ...opciones, headers, cache: "no-store" });
  };
  let res;
  try {
    res = await llamar(false);
    if (res?.status === 401) res = await llamar(true);
  } catch {
    throw new Error("Sin conexión. Tu sesión sigue abierta; inténtalo de nuevo.");
  }
  if (!res) {
    avisarAuth("Tu sesión terminó. Vuelve a entrar.", "error");
    throw new Error("sesion");
  }
  if (res.status === 401) {
    if (await usuarioActual()) throw new Error("No se pudieron cargar los datos. Tu sesión sigue abierta; inténtalo de nuevo.");
    await logout();
    avisarAuth("Tu sesión terminó. Vuelve a entrar.", "error");
    throw new Error("sesion");
  }
  return res;
}

fechaInput.value = hoy();
fechaInput.max = hoy();
// Cambiar la fecha mueve la jornada abierta a ese día, para cargar días anteriores.
async function cambiarDia(fecha) {
  if (!jornadaActual) return;
  if (!fecha || fecha > hoy()) { avisar("Elige hoy o un día anterior.", "error"); fechaInput.value = jornadaActual.fecha || hoy(); return; }
  try {
    const res = await api("/api/jornadas", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jornadaId: jornadaActual.id, fecha }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo cambiar el día");
    avisar(fecha === hoy() ? "Jornada de hoy" : `📅 Ahora cargas el ${fechaLarga(fecha)}`, "ok");
  } catch (err) {
    if (err.message !== "sesion") avisar(err.message, "error");
  }
  cargar();
}
fechaInput.addEventListener("change", () => cambiarDia(fechaInput.value));
$("volver-hoy").addEventListener("click", () => cambiarDia(hoy()));

function avisar(texto, tipo) { $("mensaje").textContent = texto; $("mensaje").className = tipo || ""; }

document.querySelectorAll("[data-cerrar]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

document.querySelectorAll("[data-registrar]").forEach((b) => b.addEventListener("click", () => {
  tipoActual = b.dataset.registrar;
  const titulos = { Gasto: "Registrar gasto", Efectivo: "Registrar cobro en efectivo", Tarjeta: "Registrar cobro con tarjeta" };
  $("dlg-titulo").textContent = titulos[tipoActual] || "Registrar " + tipoActual.toLowerCase();
  form.reset();
  avisar("");
  $("dlg-registro").showModal();
  form.monto.focus();
}));

document.querySelectorAll("[data-info]").forEach((b) => b.addEventListener("click", () => {
  if (!resumen) return;
  const r = resumen;
  const textos = {
    total: ["Total del día", `${r.otros ? `Otros ingresos ${fmt.format(r.otros)} + ` : ""}Efectivo ${fmt.format(r.efectivo)} + Tarjeta ${fmt.format(r.tarjeta)} − Gastos ${fmt.format(r.gastos)} = ${fmt.format(r.total)}`],
    mitad: ["50% del total", `La mitad del total del día (${fmt.format(r.total)}) es ${fmt.format(r.mitad)}.`],
  };
  const [titulo, texto] = textos[b.dataset.info];
  $("info-titulo").textContent = titulo;
  $("info-texto").textContent = texto;
  $("dlg-info").showModal();
}));

/* ---------- Te tengo / Me tienes (automático o manual) ---------- */

const formSaldo = $("form-saldo");

function explicarSaldo(r) {
  const acumulado = ` Lo de cada jornada se suma a lo pendiente (Te tengo ${fmt.format(pendientes.teTengo)} · Me tienes ${fmt.format(pendientes.meTienes)}), que no se borra al registrar: solo baja con «Te he pagado» o «Me has pagado».`;
  return explicarJornada(r) + acumulado;
}

function explicarJornada(r) {
  if (r.manual) return "Valores de esta jornada cargados a mano.";
  const base = "La tarjeta la cobra el otro socio y el efectivo (menos gastos) lo guardas tú; a cada uno le toca el 50%.";
  if (r.teTengo > 0) return `${base} Tienes más efectivo que tu 50%, así que le tienes ${fmt.format(r.teTengo)} al otro socio (ya descontado lo ingresado en el banco).`;
  if (r.meTienes > 0) return `${base} Lo cobrado con tarjeta supera su 50%, así que el otro socio te tiene ${fmt.format(r.meTienes)}.`;
  return `${base} En esta jornada están a mano.`;
}

document.querySelectorAll("[data-saldo]").forEach((b) => b.addEventListener("click", () => {
  if (!resumen || !jornadaActual) return;
  $("saldo-explicacion").textContent = explicarSaldo(resumen);
  $("saldo-mensaje").textContent = "";
  formSaldo.teTengo.value = resumen.manual ? resumen.teTengo : "";
  formSaldo.meTienes.value = resumen.manual ? resumen.meTienes : "";
  formSaldo.teTengo.placeholder = resumen.manual ? "" : fmt.format(resumen.teTengo);
  formSaldo.meTienes.placeholder = resumen.manual ? "" : fmt.format(resumen.meTienes);
  $("saldo-auto").hidden = !resumen.manual;
  $("dlg-saldo").showModal();
  formSaldo[b.dataset.saldo].focus();
}));

async function guardarSaldo(teTengo, meTienes) {
  try {
    const res = await api("/api/jornadas", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jornadaId: jornadaActual.id, teTengo, meTienes }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo guardar");
    $("dlg-saldo").close();
    avisar(teTengo == null && meTienes == null ? "Saldo en cálculo automático" : "✅ Saldo cargado a mano", "ok");
    cargar();
  } catch (err) {
    if (err.message === "sesion") $("dlg-saldo").close();
    else $("saldo-mensaje").textContent = err.message;
  }
}

formSaldo.addEventListener("submit", (e) => {
  e.preventDefault();
  const te = formSaldo.teTengo.value.trim();
  const me = formSaldo.meTienes.value.trim();
  guardarSaldo(te || (me ? 0 : null), me || (te ? 0 : null));
});
$("saldo-auto").addEventListener("click", () => guardarSaldo(null, null));

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const boton = form.querySelector(".principal");
  boton.disabled = true;
  try {
    const res = await api("/api/movimientos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tipo: tipoActual, monto: form.monto.value, fecha: fechaInput.value, nota: form.nota.value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "No se pudo registrar");
    $("dlg-registro").close();
    avisar(`✅ ${tipoActual} registrado: ${fmt.format(Number(data.monto))}`, "ok");
    cargar();
  } catch (err) {
    if (err.message === "sesion") $("dlg-registro").close();
    else avisar(err.message, "error");
  } finally {
    boton.disabled = false;
  }
});

async function borrar(m) {
  if (!confirm(`¿Borrar ${m.tipo.toLowerCase()} de ${fmt.format(Number(m.monto))}?`)) return;
  try {
    const res = await api("/api/movimientos?id=" + m.id, { method: "DELETE" });
    if (res.ok) { avisar("Registro borrado", "ok"); cargar(); } else avisar("No se pudo borrar", "error");
  } catch { /* sesión terminada: ya se muestra el acceso */ }
}

function pintar(r, pend) {
  resumen = r;
  pendientes = pend;
  $("v-efectivo").textContent = fmt.format(r.efectivo ?? 0);
  $("v-tarjeta").textContent = fmt.format(r.tarjeta ?? 0);
  $("v-gastos").textContent = fmt.format(r.gastos);
  $("v-banco").textContent = fmt.format(r.banco);
  $("v-total").textContent = fmt.format(r.total);
  $("v-mitad").textContent = fmt.format(r.mitad);
  pintarPendientes(pend);
  $("h-tetengo").textContent = "Hoy: " + fmt.format(r.teTengo);
  $("h-metienes").textContent = "Hoy: " + fmt.format(r.meTienes);
  document.querySelectorAll(".marca-manual").forEach((m) => { m.hidden = !r.manual; });
}

async function cargar() {
  const lista = $("lista");
  try {
    const res = await api("/api/movimientos");
    if (!res.ok) throw new Error();
    const data = await res.json();
    jornadaActual = data.jornada;
    // El día de la jornada abierta: el elegido o, si no se eligió, hoy.
    const fecha = jornadaActual.fecha || hoy();
    fechaInput.max = hoy();
    fechaInput.value = fecha;
    const anterior = fecha < hoy();
    $("aviso-dia").hidden = !anterior;
    $("aviso-dia-fecha").textContent = anterior ? fechaLarga(fecha) : "";
    $("titulo-lista").textContent = anterior ? "Registros del " + fechaLarga(fecha) : "Registros de hoy";
    pintar({ ...data.resumen, fecha }, data.pendientes ?? { teTengo: 0, meTienes: 0 });
    movimientosDia = data.movimientos;
    lista.innerHTML = "";
    if (!data.movimientos.length) { lista.innerHTML = '<li class="vacio">Aún no hay registros este día.</li>'; return; }
    for (const m of data.movimientos) {
      const li = document.createElement("li");
      const info = document.createElement("div");
      info.className = "info";
      info.textContent = m.tipo;
      if (m.nota) { const s = document.createElement("small"); s.textContent = m.nota; info.appendChild(s); }
      const monto = document.createElement("span");
      monto.className = "monto " + (m.tipo === "Ingreso en banco" ? "banco" : m.tipo);
      monto.textContent = (m.tipo === "Gasto" ? "−" : "") + fmt.format(Number(m.monto));
      const del = document.createElement("button");
      del.className = "borrar"; del.type = "button"; del.title = "Borrar"; del.textContent = "✕";
      del.addEventListener("click", () => borrar(m));
      const rec = document.createElement("button");
      rec.className = "recibo-item"; rec.type = "button"; rec.title = "Recibo"; rec.textContent = "🧾";
      rec.addEventListener("click", () => abrirRecibo(reciboMovimiento(m)));
      li.append(info, monto, rec, del);
      lista.appendChild(li);
    }
  } catch (err) {
    if (err.message !== "sesion") lista.innerHTML = '<li class="vacio">No se pudieron cargar los registros.</li>';
  }
}

/* ---------- Registrar (cerrar) la jornada ---------- */

$("registrar-jornada").addEventListener("click", async () => {
  if (!jornadaActual) return;
  if (!movimientosDia.length) { avisar("La jornada no tiene registros todavía.", "error"); return; }
  const dia = jornadaActual.fecha || hoy();
  if (!confirm(`¿Registrar la jornada del ${fechaLarga(dia)}? Total: ${fmt.format(resumen.total)}.\nSe cerrará y empezará una jornada nueva; los registros ya no se podrán modificar.`)) return;
  const boton = $("registrar-jornada");
  boton.disabled = true;
  const recibo = reciboDia();
  try {
    const res = await api("/api/jornadas", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jornadaId: jornadaActual.id, fecha: dia }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo registrar la jornada");
    avisar(dia === hoy() ? "✅ Jornada registrada. Comienza una jornada nueva." : `✅ Jornada del ${fechaLarga(dia)} registrada. Comienza una jornada nueva de hoy.`, "ok");
    await cargar();
    abrirRecibo({ ...recibo, titulo: "Recibo de la jornada" });
  } catch (err) {
    if (err.message !== "sesion") { avisar(err.message, "error"); cargar(); }
  } finally {
    boton.disabled = false;
  }
});

/* ---------- Abonos: Te he pagado / Me has pagado ---------- */

// "Te tengo" baja con "Te he pagado" (yo le pago al otro socio) y "Me tienes" con
// "Me has pagado" (el otro socio me paga). Registrar jornadas no borra lo pendiente.
const ABONOS = {
  teTengo: { titulo: "💸 Te he pagado", pendiente: "Te tengo pendiente", etiqueta: "Le pagué al otro socio", ok: "Pago al otro socio registrado" },
  meTienes: { titulo: "💵 Me has pagado", pendiente: "Me tienes pendiente", etiqueta: "El otro socio me pagó", ok: "Pago del otro socio registrado" },
};
const TIPO_CUENTA = { te_tengo: "teTengo", me_tienes: "meTienes" };
let cuentaAbono = "teTengo";

function pintarPendientes(p) {
  pendientes = p;
  $("v-tetengo").textContent = fmt.format(p.teTengo);
  $("v-metienes").textContent = fmt.format(p.meTienes);
  $("b-tetengo").classList.toggle("activo", p.teTengo > 0);
  $("b-metienes").classList.toggle("activo", p.meTienes > 0);
}

function pintarAbonos(data) {
  const c = data[cuentaAbono];
  pintarPendientes({ teTengo: data.teTengo.total, meTienes: data.meTienes.total });
  $("mt-total").textContent = fmt.format(c.total);
  $("mt-detalle").textContent =
    `Suma de "${cuentaAbono === "teTengo" ? "Te tengo" : "Me tienes"}" de todas las jornadas: ${fmt.format(c.suma)} · Abonado / ajustado: ${fmt.format(c.pagado)}`;
  const lista = $("lista-pagos");
  lista.innerHTML = "";
  const pagos = (data.pagos || []).filter((p) => (TIPO_CUENTA[p.tipo] || "meTienes") === cuentaAbono);
  if (!pagos.length) { lista.innerHTML = '<li class="vacio">Aún no hay abonos.</li>'; return; }
  for (const p of pagos) {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.className = "info";
    info.textContent = p.nota;
    const s = document.createElement("small");
    s.textContent = new Date(p.createdAt).toLocaleString("es", { dateStyle: "short", timeStyle: "short" });
    info.appendChild(s);
    const monto = document.createElement("span");
    monto.className = "monto";
    const n = Number(p.monto);
    monto.textContent = (n > 0 ? "−" : "+") + fmt.format(Math.abs(n));
    li.append(info, monto);
    lista.appendChild(li);
  }
}

async function cargarAbonos() {
  const res = await api("/api/pagos");
  if (!res.ok) throw new Error("No se pudo cargar lo pendiente");
  pintarAbonos(await res.json());
}

document.querySelectorAll("[data-abono]").forEach((b) => b.addEventListener("click", async () => {
  cuentaAbono = b.dataset.abono;
  const t = ABONOS[cuentaAbono];
  $("ab-titulo").textContent = t.titulo;
  $("ab-pendiente-txt").textContent = t.pendiente;
  $("ab-etiqueta").firstChild.textContent = t.etiqueta + " ";
  $("mt-total").textContent = fmt.format(pendientes[cuentaAbono]);
  $("mt-detalle").textContent = "";
  $("lista-pagos").innerHTML = '<li class="vacio">Cargando…</li>';
  $("mt-mensaje").textContent = "";
  $("form-pago").reset();
  $("form-total").reset();
  $("ab-nota").value = "";
  $("dlg-abono").showModal();
  $("form-pago").pago.focus();
  try { await cargarAbonos(); } catch (err) {
    if (err.message === "sesion") $("dlg-abono").close();
    else $("mt-mensaje").textContent = err.message;
  }
}));

async function enviarAbono(formulario, cuerpo, ok) {
  const boton = formulario.querySelector("button");
  boton.disabled = true;
  try {
    const res = await api("/api/pagos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cuenta: cuentaAbono, nota: $("ab-nota").value, ...cuerpo }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo guardar");
    formulario.reset();
    $("ab-nota").value = "";
    $("mt-mensaje").textContent = "";
    avisar(ok, "ok");
    await cargarAbonos();
  } catch (err) {
    if (err.message === "sesion") $("dlg-abono").close();
    else $("mt-mensaje").textContent = err.message;
  } finally {
    boton.disabled = false;
  }
}

$("form-pago").addEventListener("submit", (e) => {
  e.preventDefault();
  const monto = e.target.pago.value;
  enviarAbono(e.target, { pago: monto }, `✅ ${ABONOS[cuentaAbono].ok}: ${fmt.format(Number(monto))}`);
});
$("form-total").addEventListener("submit", (e) => {
  e.preventDefault();
  enviarAbono(e.target, { total: e.target.total.value }, "✅ Pendiente ajustado a mano");
});

/* ---------- Histórico de jornadas ---------- */

const fechaLocal = (iso) => new Date(iso).toLocaleDateString("en-CA");
const diaDe = (j) => j.fecha || fechaLocal(j.cerradaAt);
const horaCorta = (iso) => new Date(iso).toLocaleTimeString("es", { hour: "2-digit", minute: "2-digit" });

$("ver-historico").addEventListener("click", async () => {
  const lista = $("lista-historico");
  lista.innerHTML = '<li class="vacio">Cargando…</li>';
  $("dlg-historico").showModal();
  try {
    const res = await api("/api/jornadas");
    if (!res.ok) throw new Error();
    const { jornadas } = await res.json();
    lista.innerHTML = "";
    if (!jornadas.length) { lista.innerHTML = '<li class="vacio">Aún no hay jornadas registradas. Pulsa ✅ REGISTRAR al terminar el turno.</li>'; return; }
    for (const j of jornadas) {
      const li = document.createElement("li");
      const info = document.createElement("div");
      info.className = "info";
      const dia = diaDe(j);
      info.textContent = new Date(dia + "T12:00:00").toLocaleDateString("es", { weekday: "short", day: "numeric", month: "short", year: "numeric" });
      const det = document.createElement("small");
      // Las horas solo tienen sentido si la jornada se cargó el mismo día.
      const horas = dia === fechaLocal(j.cerradaAt) ? `${horaCorta(j.abiertaAt)} – ${horaCorta(j.cerradaAt)}` : "📅 cargada después";
      det.textContent = `${horas} · Efectivo ${fmt.format(j.efectivo)} · Tarjeta ${fmt.format(j.tarjeta)} · Gastos ${fmt.format(j.gastos)}`;
      info.appendChild(det);
      const monto = document.createElement("span");
      monto.className = "monto";
      monto.textContent = fmt.format(j.total);
      const saldo = document.createElement("span");
      saldo.className = "saldo-h";
      saldo.textContent = `🤝 Te tengo ${fmt.format(j.teTengo)} · 🙋 Me tienes ${fmt.format(j.meTienes)}${j.manual ? " · ✍️ manual" : ""}`;
      li.append(info, monto, saldo);
      li.addEventListener("click", () => verJornada(j));
      lista.appendChild(li);
    }
  } catch (err) {
    if (err.message === "sesion") $("dlg-historico").close();
    else lista.innerHTML = '<li class="vacio">No se pudo cargar el histórico.</li>';
  }
});

async function verJornada(j) {
  try {
    const res = await api("/api/jornadas?id=" + j.id);
    if (!res.ok) throw new Error();
    const data = await res.json();
    $("dlg-historico").close();
    abrirRecibo(reciboJornada(data.resumen, data.movimientos, diaDe(j), "Recibo de la jornada"));
  } catch (err) {
    if (err.message !== "sesion") avisar("No se pudo abrir la jornada", "error");
  }
}

/* ---------- Cierre de mes ---------- */
const formMes = $("form-mes");
const nombreMes = (mes) => {
  const t = new Date(mes + "-15T12:00:00").toLocaleDateString("es", { month: "long", year: "numeric" });
  return t.charAt(0).toUpperCase() + t.slice(1);
};
const fechaCorta = (iso) => new Date(iso + "T12:00:00").toLocaleDateString("es", { day: "numeric", month: "short", year: "numeric" });
const restarDias = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d.toLocaleDateString("en-CA"); };
$("cierre-mes").addEventListener("click", () => {
  formMes.mes.value = hoy().slice(0, 7);
  formMes.mes.max = hoy().slice(0, 7);
  $("mes-mensaje").textContent = "";
  $("dlg-mes").showModal();
});
formMes.addEventListener("submit", async (e) => {
  e.preventDefault();
  const mes = formMes.mes.value;
  const boton = formMes.querySelector(".principal");
  boton.disabled = true;
  try {
    const res = await api("/api/jornadas?mes=" + encodeURIComponent(mes));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo cargar el mes");
    $("dlg-mes").close();
    abrirRecibo(reciboPeriodo(data, "Cierre de mes", nombreMes(data.mes), "mes"));
  } catch (err) {
    if (err.message === "sesion") $("dlg-mes").close();
    else $("mes-mensaje").textContent = err.message;
  } finally {
    boton.disabled = false;
  }
});

/* ---------- Resumen por fechas ---------- */
const formRango = $("form-rango");
function ponerRango(desde, hasta) {
  formRango.desde.value = desde;
  formRango.hasta.value = hasta;
  $("rango-mensaje").textContent = "";
}
$("resumen-fechas").addEventListener("click", () => {
  if (!formRango.desde.value) ponerRango(hoy().slice(0, 8) + "01", hoy());
  formRango.desde.max = hoy();
  formRango.hasta.max = hoy();
  $("rango-mensaje").textContent = "";
  $("dlg-rango").showModal();
});
document.querySelectorAll("[data-atajo]").forEach((b) => b.addEventListener("click", () => {
  const a = b.dataset.atajo;
  if (a === "semana") ponerRango(restarDias((new Date().getDay() + 6) % 7), hoy());
  else if (a === "anio") ponerRango(hoy().slice(0, 4) + "-01-01", hoy());
  else ponerRango(restarDias(Number(a) - 1), hoy());
}));
formRango.addEventListener("submit", async (e) => {
  e.preventDefault();
  const { desde, hasta } = { desde: formRango.desde.value, hasta: formRango.hasta.value };
  if (desde > hasta) { $("rango-mensaje").textContent = "La fecha «Desde» debe ser anterior a «Hasta»."; return; }
  const boton = formRango.querySelector(".principal");
  boton.disabled = true;
  try {
    const res = await api(`/api/jornadas?desde=${encodeURIComponent(desde)}&hasta=${encodeURIComponent(hasta)}`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "No se pudo cargar el resumen");
    $("dlg-rango").close();
    const periodo = desde === hasta ? fechaLarga(desde) : `Del ${fechaCorta(desde)} al ${fechaCorta(hasta)}`;
    abrirRecibo(reciboPeriodo(data, "Resumen por fechas", periodo, "periodo"));
  } catch (err) {
    if (err.message === "sesion") $("dlg-rango").close();
    else $("rango-mensaje").textContent = err.message;
  } finally {
    boton.disabled = false;
  }
});

// Recibo de un periodo (mes o rango de fechas) con sus jornadas registradas.
function reciboPeriodo(data, titulo, periodo, nombre) {
  const r = data.resumen;
  const lineas = [];
  for (const j of data.jornadas) {
    const dia = new Date(j.fecha + "T12:00:00").toLocaleDateString("es", { weekday: "short", day: "numeric", month: "short" });
    lineas.push({ texto: dia, monto: fmt.format(j.total) });
    lineas.push({ nota: `Efectivo ${fmt.format(j.efectivo)} · Tarjeta ${fmt.format(j.tarjeta)} · Gastos ${fmt.format(j.gastos)}` });
  }
  if (!data.jornadas.length) lineas.push({ nota: `Sin jornadas registradas en este ${nombre}` });
  lineas.push({ sep: true },
    { texto: "Días trabajados", monto: String(r.dias) },
    { texto: "Jornadas", monto: String(data.jornadas.length) },
    { sep: true },
    { texto: "Efectivo", monto: fmt.format(r.efectivo) },
    { texto: "Tarjeta", monto: fmt.format(r.tarjeta) },
    ...(r.otros ? [{ texto: "Otros ingresos", monto: fmt.format(r.otros) }] : []),
    { texto: "Ingresos", monto: fmt.format(r.ingresos) },
    { texto: "Gastos", monto: "−" + fmt.format(r.gastos) },
    { texto: `Total del ${nombre}`, monto: fmt.format(r.total), fuerte: true },
    { texto: "50%", monto: fmt.format(r.mitad), fuerte: true },
    { texto: "Ingreso en banco", monto: fmt.format(r.banco) },
    ...(data.jornadas.length ? [{ texto: "Promedio por día", monto: fmt.format(r.dias ? r.total / r.dias : 0) }] : []),
    { sep: true },
    { texto: `Te tengo (${nombre})`, monto: fmt.format(r.teTengo), fuerte: r.teTengo > 0 },
    { texto: `Me tienes (${nombre})`, monto: fmt.format(r.meTienes), fuerte: r.meTienes > 0 });
  const abonos = data.abonos || [];
  const sumaAbonos = (tipo) => abonos.filter((a) => a.tipo === tipo).reduce((t, a) => t + Number(a.monto), 0);
  if (abonos.length) {
    lineas.push({ sep: true });
    for (const a of abonos) {
      const n = Number(a.monto);
      const dia = new Date(a.createdAt).toLocaleDateString("es", { day: "numeric", month: "short" });
      lineas.push({ texto: `${dia} · ${a.tipo === "te_tengo" ? "Te he pagado" : "Me has pagado"}`, monto: (n > 0 ? "−" : "+") + fmt.format(Math.abs(n)) });
      if (a.nota && a.nota !== "Te he pagado" && a.nota !== "Me has pagado") lineas.push({ nota: a.nota });
    }
    lineas.push({ texto: "Total te he pagado", monto: fmt.format(sumaAbonos("te_tengo")) },
      { texto: "Total me has pagado", monto: fmt.format(sumaAbonos("me_tienes")) });
  }
  const p = data.pendientes || { teTengo: 0, meTienes: 0 };
  lineas.push({ sep: true },
    { texto: "Te tengo pendiente (a hoy)", monto: fmt.format(p.teTengo), fuerte: true },
    { texto: "Me tienes pendiente (a hoy)", monto: fmt.format(p.meTienes), fuerte: true });
  if (data.abiertaPendiente) lineas.push({ nota: `⚠️ La jornada abierta aún no está registrada y no entra en este ${nombre}.` });
  return { titulo, fecha: data.desde, periodo, lineas };
}

/* ---------- Recibos ---------- */

// Un recibo es una lista de líneas que se muestra en pantalla, se imprime
// o se convierte en texto para WhatsApp y correo.
let reciboActual = null;

const nombreUsuario = () => {
  return usuario?.user_metadata?.full_name || usuario?.email || "";
};
const fechaLarga = (iso) =>
  new Date(iso + "T12:00:00").toLocaleDateString("es", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
const periodoRecibo = (rec) => rec.periodo || fechaLarga(rec.fecha);
const signo = (m) => (m.tipo === "Gasto" ? "−" : "");

function reciboDia() {
  const rec = reciboJornada(resumen, movimientosDia, resumen.fecha, "Recibo del día");
  rec.lineas.push({ sep: true },
    { texto: "Te tengo pendiente", monto: fmt.format(pendientes.teTengo), fuerte: pendientes.teTengo > 0 },
    { texto: "Me tienes pendiente", monto: fmt.format(pendientes.meTienes), fuerte: pendientes.meTienes > 0 });
  return rec;
}

function reciboJornada(r, movs, fecha, titulo) {
  const lineas = [];
  for (const m of [...movs].reverse()) {
    lineas.push({ texto: m.tipo, monto: signo(m) + fmt.format(Number(m.monto)) });
    if (m.nota) lineas.push({ nota: m.nota });
  }
  if (!movs.length) lineas.push({ nota: "Sin movimientos este día" });
  lineas.push({ sep: true },
    { texto: "Efectivo", monto: fmt.format(r.efectivo) },
    { texto: "Tarjeta", monto: fmt.format(r.tarjeta) },
    ...(r.otros ? [{ texto: "Otros ingresos", monto: fmt.format(r.otros) }] : []),
    { texto: "Ingresos", monto: fmt.format(r.ingresos) },
    { texto: "Gastos", monto: "−" + fmt.format(r.gastos) },
    { texto: "Total del día", monto: fmt.format(r.total), fuerte: true },
    { texto: "50%", monto: fmt.format(r.mitad), fuerte: true },
    { texto: "Ingreso en banco", monto: fmt.format(r.banco) },
    { sep: true },
    { texto: "Te tengo", monto: fmt.format(r.teTengo), fuerte: r.teTengo > 0 },
    { texto: "Me tienes", monto: fmt.format(r.meTienes), fuerte: r.meTienes > 0 },
    ...(r.manual ? [{ nota: "Te tengo / Me tienes cargados a mano" }] : []));
  return { titulo, fecha, lineas };
}

function reciboMovimiento(m) {
  const lineas = [{ texto: m.tipo, monto: signo(m) + fmt.format(Number(m.monto)), fuerte: true }];
  if (m.nota) lineas.push({ nota: m.nota });
  return { titulo: `Recibo nº ${m.id}`, fecha: m.fecha, lineas };
}

function reciboTexto(rec) {
  const filas = [`🚕 *Finanzas Taxi — ${rec.titulo}*`, periodoRecibo(rec)];
  if (nombreUsuario()) filas.push(nombreUsuario());
  filas.push("");
  for (const l of rec.lineas) {
    if (l.sep) filas.push("------------------------");
    else if (l.nota) filas.push(`   ${l.nota}`);
    else filas.push(l.fuerte ? `*${l.texto}: ${l.monto}*` : `${l.texto}: ${l.monto}`);
  }
  return filas.join("\n");
}

function abrirRecibo(rec) {
  reciboActual = rec;
  const cont = $("recibo");
  cont.innerHTML = "";
  const add = (tag, clase, texto) => {
    const el = document.createElement(tag);
    if (clase) el.className = clase;
    if (texto != null) el.textContent = texto;
    cont.appendChild(el);
    return el;
  };
  add("h2", "", "🚕 Finanzas Taxi");
  add("p", "sub", `${rec.titulo} · ${periodoRecibo(rec)}${nombreUsuario() ? " · " + nombreUsuario() : ""}`);
  for (const l of rec.lineas) {
    if (l.sep) { add("div", "sep"); continue; }
    if (l.nota) { add("div", "nota", l.nota); continue; }
    const fila = add("div", "linea" + (l.fuerte ? " fuerte" : ""));
    const a = document.createElement("span"); a.textContent = l.texto;
    const b = document.createElement("span"); b.textContent = l.monto;
    fila.append(a, b);
  }
  add("p", "pie", "Emitido el " + new Date().toLocaleString("es"));
  $("r-compartir").hidden = !navigator.share;
  $("dlg-recibo").showModal();
}

$("recibo-dia").addEventListener("click", () => { if (resumen) abrirRecibo(reciboDia()); });
$("r-imprimir").addEventListener("click", () => window.print());
$("r-whatsapp").addEventListener("click", () => {
  window.open("https://wa.me/?text=" + encodeURIComponent(reciboTexto(reciboActual)), "_blank", "noopener");
});
const correoRecibo = () => ({
  asunto: encodeURIComponent(`Finanzas Taxi — ${reciboActual.titulo} (${reciboActual.periodo || reciboActual.fecha})`),
  cuerpo: encodeURIComponent(reciboTexto(reciboActual).replace(/\*/g, "")),
});
$("r-email").addEventListener("click", () => {
  const { asunto, cuerpo } = correoRecibo();
  window.location.href = `mailto:?subject=${asunto}&body=${cuerpo}`;
});
// Gmail: en iPhone/iPad abre la app si está instalada; si no (o en otros
// dispositivos) abre la ventana de redactar de Gmail en el navegador.
$("r-gmail").addEventListener("click", () => {
  const { asunto, cuerpo } = correoRecibo();
  const web = `https://mail.google.com/mail/?view=cm&fs=1&su=${asunto}&body=${cuerpo}`;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if (!ios) { window.open(web, "_blank", "noopener"); return; }
  const respaldo = setTimeout(() => { if (!document.hidden) window.location.href = web; }, 1500);
  document.addEventListener("visibilitychange", () => clearTimeout(respaldo), { once: true });
  window.location.href = `googlegmail://co?subject=${asunto}&body=${cuerpo}`;
});
$("r-compartir").addEventListener("click", async () => {
  try {
    await navigator.share({ title: `Finanzas Taxi — ${reciboActual.titulo}`, text: reciboTexto(reciboActual).replace(/\*/g, "") });
  } catch { /* el usuario canceló */ }
});

/* ---------- Inicio ---------- */

async function iniciar() {
  try {
    // Procesa enlaces del correo: confirmación de cuenta o cambio de contraseña.
    const enlace = await procesarEnlace();
    if (enlace?.tipo === "recuperacion") {
      usuario = enlace.user;
      $("auth").hidden = false;
      formAuth.hidden = true;
      formNueva.hidden = false;
      document.querySelector(".pestanas").hidden = true;
      return;
    }
    if (enlace?.user) { mostrarApp(enlace.user); return; }
  } catch (err) {
    mostrarAuth();
    avisarAuth(mensajeError(err), "error");
    return;
  }
  // Muestra el panel enseguida con la sesión guardada y la confirma en segundo plano.
  if (usuarioGuardado()) mostrarApp(usuarioGuardado());
  const user = await usuarioActual().catch(() => usuarioGuardado());
  if (user) { if (!usuario) mostrarApp(user); else usuario = user; } else mostrarAuth();
}

iniciar();
