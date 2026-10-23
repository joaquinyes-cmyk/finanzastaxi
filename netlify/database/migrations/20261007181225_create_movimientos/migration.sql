CREATE TABLE "movimientos" (
	"id" serial PRIMARY KEY,
	"tipo" text NOT NULL,
	"monto" numeric(12,2) NOT NULL,
	"fecha" date NOT NULL,
	"nota" text DEFAULT '' NOT NULL,
	"created_at" timestamp DEFAULT now()
);
