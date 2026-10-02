# Agenda compartida

Agenda privada para Alejandro y Juan, con los temas Qiyana y Steve Fox.

## Funcionamiento

- Acceso con correo y contraseña; sesiones firmadas en cookies HttpOnly.
- Clientes y citas compartidos, guardados de forma permanente en Vercel Blob privado.
- Apariencia por cuenta y permisos administrados desde la cuenta de Alejandro.
- Actualización automática cada 30 segundos mientras la página está activa, al volver a la ventana y con el botón Actualizar.
- Conflictos de edición detectados con versiones de registros y escrituras condicionales del archivo.
- La agenda inicia vacía; no contiene datos de clientes de demostración.

## Despliegue

Vercel despliega la rama main. El proyecto debe estar conectado a su almacén Blob privado mediante BLOB_STORE_ID y OIDC. Las contraseñas derivadas con scrypt y la clave de sesión se guardan exclusivamente en state.json dentro del almacén privado; nunca en Git ni en el código del navegador.

La API /api/agenda autentica cada solicitud y aplica los permisos en el servidor. Los archivos de agenda no se sirven públicamente. No utiliza Supabase ni recursos del proyecto DnD.

## Verificación

npm ci
npm test

Las pruebas cubren autenticación, revocación de sesiones, permisos, validaciones y conflictos de edición.
