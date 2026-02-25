# Mini Vault - Agenda de Contraseñas Segura

Este proyecto es una aplicación de gestión de credenciales para servicios en línea (Netflix, Spotify, etc.), desarrollada como parte de la Prueba Técnica para la Universidad Católica Boliviana "San Pablo".

## 1. Stack Elegido y Por Qué

### Frontend
- **React 19**: Elegido por su eficiencia en el manejo del estado y su ecosistema robusto.
- **Tailwind CSS**: Para un diseño rápido, responsivo y altamente personalizable sin salir del HTML/JSX.
- **Motion (Framer Motion)**: Para proporcionar una experiencia de usuario fluida con animaciones de transición y estados de carga.
- **Lucide React**: Set de iconos consistente y ligero.

### Backend
- **Node.js & Express**: Entorno de ejecución estándar para JavaScript en el servidor, ideal para APIs REST rápidas.
- **JWT (JSON Web Tokens)**: Para una autenticación segura y sin estado (stateless).
- **Bcrypt.js**: Para el hashing seguro de la contraseña maestra del usuario.
- **Crypto (AES-256-CBC)**: Para el cifrado reversible de las contraseñas de los servicios, cumpliendo con el requisito de seguridad.

### Base de Datos
- **SQLite (via better-sqlite3)**: Se eligió por ser una base de datos relacional ligera que no requiere un servidor externo, facilitando la portabilidad y el despliegue del proyecto técnico, manteniendo persistencia real.

---

## 2. Requisitos para Ejecutar

- **Node.js**: Versión 18.x o superior.
- **npm**: Versión 9.x o superior.
- **Sistema Operativo**: Windows, macOS o Linux.

---

## 3. Pasos de Instalación

1.  **Descargar/Clonar el repositorio**:
    ```bash
    git clone <url-del-repositorio>
    cd mini_vault
    ```

2.  **Instalar dependencias**:
    ```bash
    npm install
    ```

3.  **Configurar variables de entorno**:
    - Crea un archivo `.env` en la raíz del proyecto.
    - Puedes basarte en el archivo `.env.example`.
    - **Importante**: La `ENCRYPTION_KEY` debe tener exactamente 32 caracteres para el cifrado AES-256.

    Ejemplo de `.env`:
    ```env
    ENCRYPTION_KEY="una_clave_secreta_de_32_caracteres"
    JWT_SECRET="mi_secreto_para_tokens_jwt"
    ```

---

## 4. Cómo correr Migraciones / Seed

La aplicación está diseñada para ser **auto-gestionada**:
- **Migraciones**: No es necesario correr comandos manuales. Al iniciar la aplicación (`npm run dev`), el archivo `src/db.ts` verifica la existencia de las tablas y las crea automáticamente si no existen.
- **Seed**: No se incluye un script de seed por defecto para garantizar la seguridad de los datos. Se recomienda registrar un usuario nuevo directamente desde la interfaz de "Register".

---

## 5. Variables de Entorno Requeridas

| Variable | Descripción | Ejemplo |
| :--- | :--- | :--- |
| `ENCRYPTION_KEY` | Clave de 32 bytes para cifrar contraseñas de servicios. | `a_very_secret_32_chars_long_key_!!` |
| `JWT_SECRET` | Clave para firmar los tokens de sesión. | `super_secret_jwt_key` |
| `GEMINI_API_KEY` | (Opcional) Usada por el entorno de AI Studio. | `AIza...` |

---

## 6. Usuarios de Prueba

No se han pre-cargado usuarios de prueba por razones de seguridad (hashing de contraseñas). 
**Instrucciones para probar:**
1. Inicia la app con `npm run dev`.
2. Ve a la pestaña **"Register"**.
3. Crea una cuenta con cualquier correo y contraseña.
4. Inicia sesión con esas credenciales para acceder a tu bóveda personal.

---

## Ejecución en Desarrollo

Para iniciar el servidor y el cliente simultáneamente:
```bash
npm run dev
```
La aplicación estará disponible en `http://localhost:3000`.
