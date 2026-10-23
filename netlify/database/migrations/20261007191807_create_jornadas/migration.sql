CREATE TABLE "jornadas" (
	"id" serial PRIMARY KEY,
	"user_id" text NOT NULL,
	"abierta_at" timestamp with time zone DEFAULT now() NOT NULL,
	"cerrada_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "movimientos" ADD COLUMN "jornada_id" integer;--> statement-breakpoint
CREATE INDEX "jornadas_user_cerrada_idx" ON "jornadas" ("user_id","cerrada_at");--> statement-breakpoint
CREATE UNIQUE INDEX "jornadas_una_abierta_idx" ON "jornadas" ("user_id") WHERE cerrada_at is null;--> statement-breakpoint
CREATE INDEX "movimientos_jornada_idx" ON "movimientos" ("jornada_id");--> statement-breakpoint
ALTER TABLE "movimientos" ADD CONSTRAINT "movimientos_jornada_id_jornadas_id_fkey" FOREIGN KEY ("jornada_id") REFERENCES "jornadas"("id");