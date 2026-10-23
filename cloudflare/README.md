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

## Si olvidas la contraseña (sin correo)

Esta versión no envía correos. En su lugar cada cuenta tiene un **código de recuperación**:

- Al crear la cuenta, la app muestra un código como `ABCD-EFGH-JKLM-NPQR`. Se ve **una sola vez**:
  guárdalo en un sitio seguro (por ejemplo, las notas del móvil).
- Si olvidas la contraseña, en la pantalla de entrada pulsa **«¿Olvidaste tu contraseña?»**, escribe
  tu correo, el código y una contraseña nueva. Al usarlo se cierran las sesiones abiertas y la app
  muestra un **código nuevo**: el anterior deja de valer.
- Las cuentas creadas antes de esta función no tienen código. Entra a la cuenta y pulsa **🔑 Código**
  (arriba, junto a «Descargar copia»): pide la contraseña y genera uno. Desde ahí también se puede
  generar uno nuevo cuando quieras.

### Si alguien pierde también el código (restablecer como administrador)

1. En el Worker, en **Configuración → Variables y secretos**, crea el secreto `ADMIN_KEY` con una clave
   larga y al azar (**16 caracteres o más**; si es más corta, esta función queda desactivada).
2. Abre `https://TU-WORKER.workers.dev/api/admin-restablecer` desde el móvil o el ordenador.
3. Escribe la clave de administrador, el correo de la cuenta y una contraseña nueva.
4. La página muestra el código de recuperación nuevo de esa cuenta. Pásaselo a su dueño junto con
   la contraseña nueva.

Si no existe `ADMIN_KEY`, esa dirección responde «No encontrado». Para desactivarla de nuevo,
borra el secreto.

## Diferencias con la versión de Netlify

- Al crear una cuenta se entra directamente, sin correo de confirmación.
- No se envían correos: la recuperación de contraseña usa el código de recuperación de arriba.

## Probarla en tu ordenador

```
npx wrangler dev
```
