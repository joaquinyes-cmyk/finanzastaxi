CREATE TABLE "pagos_socio" (
	"id" serial PRIMARY KEY,
	"user_id" text NOT NULL,
	"monto" numeric(12,2) NOT NULL,
	"nota" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "pagos_socio_user_idx" ON "pagos_socio" ("user_id");