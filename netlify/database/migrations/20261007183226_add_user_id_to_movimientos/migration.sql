ALTER TABLE "movimientos" ADD COLUMN "user_id" text DEFAULT '' NOT NULL;--> statement-breakpoint
CREATE INDEX "movimientos_user_fecha_idx" ON "movimientos" ("user_id","fecha");