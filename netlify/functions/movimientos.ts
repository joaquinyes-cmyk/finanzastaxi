import type { Config } from "@netlify/functions";
import { getIdentityConfig } from "@netlify/identity";
import { and, asc, desc, eq, isNotNull, isNull, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { jornadas, movimientos, pagosSocio } from "../../db/schema.js";

// "Ingreso" ya no se registra desde la app, pero los registros antiguos siguen sumando.
const TIPOS = ["Efectivo", "Tarjeta", "Gasto", "Ingreso en banco"] as const;
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;

const hoy = () => new Date().toISOString().slice(0, 10);
// Fecha válida para una jornada: con formato correcto y que no sea futura (se deja un
// día de margen porque el servidor usa UTC y el móvil la hora local).
function fechaValida(v: unknown): string | null {
  if (typeof v !== "string" || !FECHA_RE.test(v) || Number.isNaN(Date.parse(v))) return null;
  const manana = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  return v <= manana ? v : null;
}
// Día de una jornada: el cargado o, en las antiguas, el día en que se registró.
const diaJornada = sql<string>`coalesce(${jornadas.fecha}, (${jornadas.cerradaAt})::date)::text`;
const sumaTipo = (tipo: string) =>
  sql<string>`coalesce(sum(case when ${movimientos.tipo} = ${tipo} then ${movimientos.monto} else 0 end), 0)`;

const sumas = {
  otros: sumaTipo("Ingreso"),
  efectivo: sumaTipo("Efectivo"),
  tarjeta: sumaTipo("Tarjeta"),
  gastos: sumaTipo("Gasto"),
  banco: sumaTipo("Ingreso en banco"),
};
type Sumas = { otros: string; efectivo: string; tarjeta: string; gastos: string; banco: string };
// Lo ganado suma los ingresos generales, en efectivo y con tarjeta.
const ganado = (f: Sumas) => Number(f.otros) + Number(f.efectivo) + Number(f.tarjeta);

function totales(f: Sumas) {
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
const saldoAuto = (f: Sumas) =>
  (Number(f.otros) + Number(f.efectivo) - Number(f.gastos) - Number(f.tarjeta)) / 2 - Number(f.banco);

type Saldo = { teTengo: number; meTienes: number; manual: boolean };
const separar = (saldo: number) => ({ teTengo: saldo > 0 ? saldo : 0, meTienes: saldo < 0 ? -saldo : 0 });

// Saldo entre socios de cada jornada del usuario. Cada jornada empieza en 0: el saldo
// sale solo de sus registros, o de los valores cargados a mano si los tiene.
async function saldos(userId: string) {
  const porJornada = await db
    .select({ jornadaId: movimientos.jornadaId, ...sumas })
    .from(movimientos)
    .where(eq(movimientos.userId, userId))
    .groupBy(movimientos.jornadaId);
  const lista = await db
    .select({ id: jornadas.id, te: jornadas.teTengoManual, me: jornadas.meTienesManual })
    .from(jornadas)
    .where(eq(jornadas.userId, userId));
  const sumasDe = new Map(porJornada.map((f) => [f.jornadaId, f]));
  const resultado = new Map<number, Saldo>();
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

const r2 = (n: number) => Math.round(n * 100) / 100;
// Cuentas entre socios y el tipo con que se guardan sus abonos.
const CUENTAS = { teTengo: "te_tengo", meTienes: "me_tienes" } as const;
type Cuenta = keyof typeof CUENTAS;
const NOTA_ABONO: Record<Cuenta, string> = { teTengo: "Te he pagado", meTienes: "Me has pagado" };

// Lo pendiente entre socios: la suma de "Te tengo" / "Me tienes" de todas las jornadas
// (también la abierta) menos lo ya abonado. Registrar una jornada no lo borra; solo
// baja con los abonos.
async function pendientes(userId: string) {
  const suma = { teTengo: 0, meTienes: 0 };
  for (const s of (await saldos(userId)).values()) {
    suma.teTengo += s.teTengo;
    suma.meTienes += s.meTienes;
  }
  const abonos = await db
    .select({ tipo: pagosSocio.tipo, pagado: sql<string>`coalesce(sum(${pagosSocio.monto}), 0)` })
    .from(pagosSocio)
    .where(eq(pagosSocio.userId, userId))
    .groupBy(pagosSocio.tipo);
  const cuenta = (c: Cuenta) => {
    const pagado = Number(abonos.find((a) => a.tipo === CUENTAS[c])?.pagado ?? 0);
    return { suma: r2(suma[c]), pagado: r2(pagado), total: r2(suma[c] - pagado) };
  };
  return { teTengo: cuenta("teTengo"), meTienes: cuenta("meTienes") };
}
const totalesPendientes = async (userId: string) => {
  const p = await pendientes(userId);
  return { teTengo: p.teTengo.total, meTienes: p.meTienes.total };
};

// Resumen de una jornada y su saldo entre socios.
async function resumen(userId: string, jornadaId: number) {
  const [jor] = await db
    .select(sumas)
    .from(movimientos)
    .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, jornadaId)));
  const saldo = (await saldos(userId)).get(jornadaId) ?? { teTengo: 0, meTienes: 0, manual: false };
  return { ...totales(jor), ...saldo };
}

// Devuelve la jornada abierta del usuario, creándola si no existe. Los registros
// anteriores a las jornadas (sin jornada) pasan a la jornada abierta.
async function jornadaAbierta(userId: string) {
  const buscar = () =>
    db.select().from(jornadas).where(and(eq(jornadas.userId, userId), isNull(jornadas.cerradaAt))).limit(1);
  let [jornada] = await buscar();
  if (!jornada) {
    await db.insert(jornadas).values({ userId }).onConflictDoNothing();
    [jornada] = await buscar();
  }
  await db
    .update(movimientos)
    .set({ jornadaId: jornada.id })
    .where(and(eq(movimientos.userId, userId), isNull(movimientos.jornadaId)));
  return jornada;
}

function leerMovimiento(body: any) {
  const tipo = TIPOS.find((t) => t === body?.tipo);
  if (!tipo) return { error: "Tipo de movimiento no válido" };
  const monto = Number(body?.monto);
  if (!Number.isFinite(monto) || monto <= 0) return { error: "El monto debe ser mayor que 0" };
  const fecha = typeof body?.fecha === "string" && FECHA_RE.test(body.fecha) ? body.fecha : hoy();
  const nota = typeof body?.nota === "string" ? body.nota.slice(0, 500) : "";
  return { valores: { tipo, monto: monto.toFixed(2), fecha, nota } };
}

const BLOQUEADO = "Este registro pertenece a una jornada ya registrada y no se puede modificar.";

async function usuarioActual(req: Request): Promise<{ id: string } | null> {
  let auth = req.headers.get("authorization");
  if (!auth) {
    const cookie = req.headers.get("cookie")?.match(/(?:^|;\s*)nf_jwt=([^;]+)/)?.[1];
    if (!cookie) return null;
    try {
      auth = `Bearer ${decodeURIComponent(cookie)}`;
    } catch {
      return null;
    }
  }
  if (!/^Bearer \S+$/i.test(auth)) return null;
  // Primero el Identity del mismo despliegue que abrió el usuario; después el configurado.
  const urls = [new URL("/.netlify/identity", req.url).href, getIdentityConfig()?.url]
    .filter((u): u is string => Boolean(u))
    .map((u) => u.replace(/\/$/, ""));
  let fallo: unknown = null;
  for (const identityUrl of [...new Set(urls)]) {
    try {
      const res = await fetch(`${identityUrl}/user`, {
        headers: { Authorization: auth },
        cache: "no-store",
        signal: AbortSignal.timeout(8000),
      });
      if (res.status === 401 || res.status === 403) return null;
      if (!res.ok) throw new Error(`Identity respondió ${res.status}`);
      const data = await res.json();
      if (typeof data?.id === "string" && data.id) return { id: data.id };
      throw new Error("Respuesta de Identity no válida");
    } catch (err) {
      fallo = err;
    }
  }
  throw fallo ?? new Error("Identity no disponible");
}

async function manejar(req: Request) {
  let user: { id: string } | null;
  try {
    user = await usuarioActual(req);
  } catch {
    return Response.json({ error: "No se pudo comprobar la sesión. Inténtalo de nuevo sin cerrar la app." }, {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }
  if (!user) {
    return Response.json({ error: "Inicia sesión para continuar" }, { status: 401, headers: { "Cache-Control": "no-store" } });
  }
  const userId = user.id;
  const url = new URL(req.url);
  const id = Number(url.searchParams.get("id"));
  const idValido = Number.isInteger(id) && id > 0;

  /* ----- Abonos entre socios: "Te he pagado" / "Me has pagado" ----- */
  if (url.pathname.endsWith("/me-tienes") || url.pathname.endsWith("/pagos")) {
    if (req.method === "GET") {
      const pagos = await db
        .select()
        .from(pagosSocio)
        .where(eq(pagosSocio.userId, userId))
        .orderBy(desc(pagosSocio.createdAt))
        .limit(100);
      return Response.json({ ...(await pendientes(userId)), pagos });
    }
    if (req.method === "POST") {
      // { cuenta, pago } abona a esa cuenta; { cuenta, total } fija el pendiente a mano.
      // Sin cuenta se usa "meTienes" (versiones anteriores de la app).
      const body = await req.json().catch(() => null);
      const cuenta: Cuenta = body?.cuenta === "teTengo" ? "teTengo" : "meTienes";
      const nota = typeof body?.nota === "string" ? body.nota.trim().slice(0, 500) : "";
      let monto: number;
      if (body?.total !== undefined) {
        const total = Number(body.total);
        if (body.total === "" || !Number.isFinite(total) || total < 0) {
          return Response.json({ error: "El total debe ser un número de 0 o más" }, { status: 400 });
        }
        monto = (await pendientes(userId))[cuenta].total - total;
      } else {
        monto = Number(body?.pago);
        if (!Number.isFinite(monto) || monto <= 0) {
          return Response.json({ error: "El pago debe ser mayor que 0" }, { status: 400 });
        }
      }
      if (Math.abs(monto) >= 0.005) {
        await db.insert(pagosSocio).values({
          userId,
          tipo: CUENTAS[cuenta],
          monto: monto.toFixed(2),
          nota: nota || (body?.total !== undefined ? "Total ajustado a mano" : NOTA_ABONO[cuenta]),
        });
      }
      return Response.json(await pendientes(userId), { status: 201 });
    }
    return new Response("Method not allowed", { status: 405 });
  }

  /* ----- Historial de jornadas ----- */
  if (url.pathname.endsWith("/jornadas")) {
    if (req.method === "GET" && idValido) {
      const [jornada] = await db.select().from(jornadas).where(and(eq(jornadas.id, id), eq(jornadas.userId, userId)));
      if (!jornada) return Response.json({ error: "Jornada no encontrada" }, { status: 404 });
      const rows = await db
        .select()
        .from(movimientos)
        .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, id)))
        .orderBy(desc(movimientos.createdAt));
      return Response.json({ jornada, resumen: await resumen(userId, id), movimientos: rows });
    }
    if (req.method === "GET") {
      // ?mes=AAAA-MM devuelve el cierre de ese mes y ?desde=…&hasta=… el resumen de esas
      // fechas: sus jornadas registradas y los totales.
      const mes = url.searchParams.get("mes");
      if (mes !== null && !/^\d{4}-(0[1-9]|1[0-2])$/.test(mes)) {
        return Response.json({ error: "Mes no válido" }, { status: 400 });
      }
      let desde: string | null = null;
      let hasta: string | null = null;
      if (mes) {
        desde = `${mes}-01`;
        const [y, m] = mes.split("-").map(Number);
        hasta = new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10);
      } else if (url.searchParams.has("desde") || url.searchParams.has("hasta")) {
        const leer = (v: string | null) => (v && FECHA_RE.test(v) && !Number.isNaN(Date.parse(v)) ? v : null);
        desde = leer(url.searchParams.get("desde"));
        hasta = leer(url.searchParams.get("hasta"));
        if (!desde || !hasta) return Response.json({ error: "Elige las dos fechas" }, { status: 400 });
        if (desde > hasta) return Response.json({ error: "La fecha «Desde» debe ser anterior a «Hasta»" }, { status: 400 });
      }
      const rango = desde !== null && hasta !== null;
      const filas = await db
        .select({ id: jornadas.id, fecha: diaJornada, abiertaAt: jornadas.abiertaAt, cerradaAt: jornadas.cerradaAt, ...sumas })
        .from(jornadas)
        .leftJoin(movimientos, eq(movimientos.jornadaId, jornadas.id))
        .where(and(
          eq(jornadas.userId, userId),
          isNotNull(jornadas.cerradaAt),
          rango ? sql`${diaJornada} between ${desde} and ${hasta}` : undefined,
        ))
        .groupBy(jornadas.id)
        .orderBy(rango ? asc(diaJornada) : desc(diaJornada), rango ? asc(jornadas.cerradaAt) : desc(jornadas.cerradaAt))
        .limit(rango ? 2000 : 200);
      const saldoDe = await saldos(userId);
      const lista = filas.map((f) => ({
        id: f.id,
        fecha: f.fecha,
        abiertaAt: f.abiertaAt,
        cerradaAt: f.cerradaAt,
        ...totales(f),
        ...(saldoDe.get(f.id) ?? { teTengo: 0, meTienes: 0, manual: false }),
      }));
      if (!rango) return Response.json({ jornadas: lista });
      const suma = (k: "otros" | "efectivo" | "tarjeta" | "gastos" | "banco" | "teTengo" | "meTienes") =>
        Math.round(lista.reduce((t, j) => t + j[k], 0) * 100) / 100;
      const f = { otros: suma("otros"), efectivo: suma("efectivo"), tarjeta: suma("tarjeta"), gastos: suma("gastos"), banco: suma("banco") };
      const t = totales({
        otros: String(f.otros), efectivo: String(f.efectivo), tarjeta: String(f.tarjeta), gastos: String(f.gastos), banco: String(f.banco),
      });
      const abierta = await jornadaAbierta(userId);
      const [{ sinRegistrar }] = await db
        .select({ sinRegistrar: sql<number>`count(*)::int` })
        .from(movimientos)
        .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)));
      const diaAbierta = abierta.fecha ?? hoy();
      // Abonos hechos dentro del periodo (por el día en que se registraron).
      const abonos = await db
        .select({ tipo: pagosSocio.tipo, monto: pagosSocio.monto, nota: pagosSocio.nota, createdAt: pagosSocio.createdAt })
        .from(pagosSocio)
        .where(and(
          eq(pagosSocio.userId, userId),
          sql`(${pagosSocio.createdAt})::date between ${desde} and ${hasta}`,
        ))
        .orderBy(asc(pagosSocio.createdAt));
      return Response.json({
        mes,
        desde,
        hasta,
        jornadas: lista,
        abonos,
        resumen: {
          ...t,
          teTengo: suma("teTengo"),
          meTienes: suma("meTienes"),
          dias: new Set(lista.map((j) => j.fecha)).size,
        },
        // La jornada abierta todavía no entra en el resumen; se avisa si es del periodo.
        abiertaPendiente: sinRegistrar > 0 && diaAbierta >= desde! && diaAbierta <= hasta!,
        pendientes: await totalesPendientes(userId),
      });
    }
    if (req.method === "POST") {
      // Registrar (cerrar) la jornada abierta y abrir una nueva.
      const body = await req.json().catch(() => null);
      const abierta = await jornadaAbierta(userId);
      if (Number(body?.jornadaId) !== abierta.id) {
        return Response.json({ error: "Esta jornada ya se registró. Recarga la pantalla." }, { status: 409 });
      }
      const [{ n }] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(movimientos)
        .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)));
      if (!n) return Response.json({ error: "La jornada no tiene registros todavía." }, { status: 400 });
      // La jornada queda registrada en su día (puede ser un día anterior) y sus
      // registros toman esa misma fecha.
      const fecha = fechaValida(body?.fecha) ?? abierta.fecha ?? hoy();
      await db
        .update(movimientos)
        .set({ fecha })
        .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)));
      const [cerrada] = await db
        .update(jornadas)
        .set({ cerradaAt: new Date(), fecha })
        .where(and(eq(jornadas.id, abierta.id), eq(jornadas.userId, userId), isNull(jornadas.cerradaAt)))
        .returning();
      if (!cerrada) return Response.json({ error: "Esta jornada ya se registró. Recarga la pantalla." }, { status: 409 });
      const nueva = await jornadaAbierta(userId);
      return Response.json({ cerrada, nueva }, { status: 201 });
    }
    if (req.method === "PUT") {
      // Cargar a mano "Te tengo" / "Me tienes" de la jornada abierta (null = automático).
      const body = await req.json().catch(() => null);
      const abierta = await jornadaAbierta(userId);
      if (Number(body?.jornadaId) !== abierta.id) {
        return Response.json({ error: "Esta jornada ya se registró. Recarga la pantalla." }, { status: 409 });
      }
      if (body && "fecha" in body) {
        // Cambiar el día de la jornada abierta (para cargar un día anterior).
        const fecha = fechaValida(body.fecha);
        if (!fecha) return Response.json({ error: "Elige un día de hoy o anterior" }, { status: 400 });
        await db
          .update(jornadas)
          .set({ fecha })
          .where(and(eq(jornadas.id, abierta.id), eq(jornadas.userId, userId), isNull(jornadas.cerradaAt)));
        await db
          .update(movimientos)
          .set({ fecha })
          .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)));
        return Response.json({ fecha });
      }
      const leerValor = (v: unknown) => {
        if (v === null || v === undefined || v === "") return null;
        const n = Number(v);
        return Number.isFinite(n) && n >= 0 ? n.toFixed(2) : undefined;
      };
      const teTengoManual = leerValor(body?.teTengo);
      const meTienesManual = leerValor(body?.meTienes);
      if (teTengoManual === undefined || meTienesManual === undefined) {
        return Response.json({ error: "Los montos deben ser números de 0 o más" }, { status: 400 });
      }
      await db
        .update(jornadas)
        .set({ teTengoManual, meTienesManual })
        .where(and(eq(jornadas.id, abierta.id), eq(jornadas.userId, userId), isNull(jornadas.cerradaAt)));
      return Response.json({ resumen: await resumen(userId, abierta.id) });
    }
    return new Response("Method not allowed", { status: 405 });
  }

  /* ----- Registros de la jornada abierta ----- */
  if (req.method === "GET" && url.searchParams.has("todo")) {
    const rows = await db
      .select({
        fecha: movimientos.fecha,
        tipo: movimientos.tipo,
        monto: movimientos.monto,
        nota: movimientos.nota,
        abiertaAt: jornadas.abiertaAt,
        cerradaAt: jornadas.cerradaAt,
      })
      .from(movimientos)
      .leftJoin(jornadas, eq(jornadas.id, movimientos.jornadaId))
      .where(eq(movimientos.userId, userId))
      .orderBy(asc(movimientos.jornadaId), asc(movimientos.createdAt));
    return Response.json({ movimientos: rows });
  }

  const abierta = await jornadaAbierta(userId);

  if (req.method === "GET") {
    const rows = await db
      .select()
      .from(movimientos)
      .where(and(eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)))
      .orderBy(desc(movimientos.createdAt));
    return Response.json({
      jornada: abierta,
      resumen: await resumen(userId, abierta.id),
      pendientes: await totalesPendientes(userId),
      movimientos: rows,
    });
  }

  if (req.method === "POST" || req.method === "PUT") {
    const leido = leerMovimiento(await req.json().catch(() => null));
    if (!leido.valores) return Response.json({ error: leido.error }, { status: 400 });
    if (req.method === "POST") {
      const [row] = await db
        .insert(movimientos)
        .values({ userId, jornadaId: abierta.id, ...leido.valores, fecha: abierta.fecha ?? leido.valores.fecha })
        .returning();
      return Response.json(row, { status: 201 });
    }
    if (!idValido) return Response.json({ error: "Id no válido" }, { status: 400 });
    const [row] = await db
      .update(movimientos)
      .set({ ...leido.valores, fecha: abierta.fecha ?? leido.valores.fecha })
      .where(and(eq(movimientos.id, id), eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)))
      .returning();
    if (!row) return Response.json({ error: BLOQUEADO }, { status: 409 });
    return Response.json(row);
  }

  if (req.method === "DELETE") {
    if (!idValido) return Response.json({ error: "Id no válido" }, { status: 400 });
    const borrados = await db
      .delete(movimientos)
      .where(and(eq(movimientos.id, id), eq(movimientos.userId, userId), eq(movimientos.jornadaId, abierta.id)))
      .returning({ id: movimientos.id });
    if (!borrados.length) return Response.json({ error: BLOQUEADO }, { status: 409 });
    return new Response(null, { status: 204 });
  }

  return new Response("Method not allowed", { status: 405 });
}

export default async (req: Request) => {
  try {
    return await manejar(req);
  } catch (err) {
    console.error("Error en la API", err);
    return Response.json({ error: "No se pudo guardar o leer los datos. Inténtalo de nuevo." }, { status: 500 });
  }
};

export const config: Config = {
  path: ["/api/movimientos", "/api/jornadas", "/api/me-tienes", "/api/pagos"],
};
