# Finanzas Taxi en Cloudflare

Esta carpeta tiene el servidor de una versión de Finanzas Taxi que funciona por completo en Cloudflare, sin
depender de Netlify. Usa la misma pantalla que la versión de Netlify, pero tiene su propio
servidor (Cloudflare Worker), su propia base de datos (Cloudflare D1) y sus propias cuentas.

**Importante:** es una versión independiente. Empieza vacía: las cuentas y los registros de la
versión de Netlify no aparecen aquí, y lo que se cargue aquí no aparece en Netlify.

## Publicarla desde GitHub

1. Entra en el panel de Cloudflare y ve a **Workers y Pages → Crear → Importar un repositorio**.
2. Conecta GitHub y elige el repositorio `joaquinyes-cmyk/finanzastaxi`, rama `main`.
3. Completa la configuración así:
   - **Nombre del proyecto:** `finanzastaxi` (tiene que coincidir con `"name"` en `wrangler.jsonc`,
     en la raíz del repositorio).
   - **Comando de compilación:** déjalo vacío o pon `npm run build`.
   - **Comando de despliegue:** `npx wrangler deploy` (el que viene por defecto).
   - **Directorio raíz:** déjalo vacío (la raíz del repositorio).
4. Pulsa **Desplegar**. En el primer despliegue Cloudflare crea la base de datos
   `finanzastaxi-db`, y la app crea sus tablas sola la primera vez que se abre.

A partir de ahí, cada cambio que se sube a `main` publica una nueva versión en Cloudflare
(y también en Netlify, que sigue funcionando igual).

Si Cloudflare no crea la base de datos solo, créala en **Almacenamiento y bases de datos → D1 →
Crear** con el nombre `finanzastaxi-db`, copia su id y pégalo en `database_id` dentro de
`wrangler.jsonc` (en la raíz del repositorio).

## Ajustes opcionales

En el Worker, en **Configuración → Variables y secretos**:

- `CORREOS_PERMITIDOS`: correos separados por comas (por ejemplo `yo@correo.com,socio@correo.com`).
  Si se pone, solo esos correos pueden crear una cuenta. Si no, cualquiera puede registrarse,
  aunque cada persona solo ve sus propios datos.
- `JWT_SECRET` (como secreto): clave para firmar las sesiones. Si no se pone, la app genera
  una al azar y la guarda en la base de datos.

## Diferencias con la versión de Netlify

- Al crear una cuenta se entra directamente, sin correo de confirmación.
- Esta versión no envía correos, así que **«¿Olvidaste tu contraseña?» no funciona**. Guarda bien
  la contraseña.

## Probarla en tu ordenador

```
npx wrangler dev
```
