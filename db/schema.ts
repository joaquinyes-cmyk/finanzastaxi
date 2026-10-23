import { pgTable, serial, text, timestamp, numeric, date, index, integer, uniqueIndex } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

// Una jornada agrupa los registros de un turno. Mientras está abierta (cerradaAt nula)
// sus registros se pueden editar; al registrarla queda cerrada y pasa al historial.
export const jornadas = pgTable("jornadas", {
  id: serial().primaryKey(),
  userId: text("user_id").notNull(),
  abiertaAt: timestamp("abierta_at", { withTimezone: true }).notNull().defaultNow(),
  cerradaAt: timestamp("cerrada_at", { withTimezone: true }),
  // Valores de "Te tengo" / "Me tienes" cargados a mano. Si alguno está puesto,
  // fija el saldo entre socios en esta jornada en lugar del cálculo automático.
  teTengoManual: numeric("te_tengo_manual", { precision: 12, scale: 2 }),
  meTienesManual: numeric("me_tienes_manual", { precision: 12, scale: 2 }),
  // Día trabajado en la jornada. Permite cargar días anteriores; si es nulo (jornadas
  // antiguas) se toma el día en que se registró.
  fecha: date(),
}, (t) => [
  index("jornadas_user_cerrada_idx").on(t.userId, t.cerradaAt),
  // Como máximo una jornada abierta por usuario.
  uniqueIndex("jornadas_una_abierta_idx").on(t.userId).where(sql`cerrada_at is null`),
]);

export const movimientos = pgTable("movimientos", {
  id: serial().primaryKey(),
  // Id del usuario de Netlify Identity dueño del registro.
  userId: text("user_id").notNull().default(""),
  jornadaId: integer("jornada_id").references(() => jornadas.id),
  tipo: text().notNull(),
  monto: numeric({ precision: 12, scale: 2 }).notNull(),
  fecha: date().notNull(),
  nota: text().notNull().default(""),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("movimientos_user_fecha_idx").on(t.userId, t.fecha),
  index("movimientos_jornada_idx").on(t.jornadaId),
]);

// Abonos entre socios que descuentan de lo pendiente: con tipo "me_tienes" el otro
// socio me pagó (baja "Me tienes"); con "te_tengo" yo le pagué (baja "Te tengo").
// Lo pendiente es la suma de esa columna en todas las jornadas menos sus abonos.
// Un monto negativo sube el pendiente (cuando se fija a mano).
export const pagosSocio = pgTable("pagos_socio", {
  id: serial().primaryKey(),
  userId: text("user_id").notNull(),
  tipo: text().notNull().default("me_tienes"),
  monto: numeric({ precision: 12, scale: 2 }).notNull(),
  nota: text().notNull().default(""),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index("pagos_socio_user_idx").on(t.userId)]);
