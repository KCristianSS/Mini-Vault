# Mini Vault — Agenda de Contraseñas de Servicios

**Proyecto:** Prueba Técnica — *Mini Vault: Agenda de Contraseñas de Servicios*  
**Curso:** Tecnologías Web II — Universidad Católica Boliviana “San Pablo”.  
Referencia del enunciado: Documento entregado por la cátedra. :contentReference[oaicite:1]{index=1}

---

## 1. Stack elegido y por qué
> *Nota:* No se incluye código; aquí se explica la elección de stack sugerida para implementación.

- **Backend:** Node.js + Express (o Fastify) — por rapidez, ecosistema y compatibilidad con JSON Web Tokens.
- **Base de datos:** PostgreSQL — relacional, ACID, UUID nativo y fácil migración.
- **Frontend:** React + Vite (o Create React App). Componentes simples y estado local/global según necesidad.
- **Autenticación:** JWT (acceso con token) o sesiones con cookies (opción).
- **Cifrado de credenciales:** AES-256-GCM con clave en variable de entorno `ENCRYPTION_KEY`.
- **Hash de contraseñas de usuarios:** bcrypt (solo hash, no reversible).
- **Formato de API sugerido:** RESTful (endpoints listados en *API.md*).

Motivación: stack estándar en web, fácil de montar en local y desplegar en Heroku/Render/Vercel + managed DB.

---

## 2. Requisitos para ejecutar (resumen, sin código)
- Node.js 18+ instalado (si se implementa backend sugerido).
- PostgreSQL 13+ (o SQLite para desarrollo simplificado).
- Variables de entorno (ver `.env.example`).
- Ejecutar migraciones y seed (comandos documentados abajo).

---

## 3. Variables de entorno (ejemplo)
Ver `.env.example` incluido en repo.

- `DATABASE_URL` — URL de conexión a BD.
- `PORT` — puerto del API.
- `JWT_SECRET` — secreto para firma de JWT.
- `ENCRYPTION_KEY` — clave para cifrar/descifrar contraseñas de servicios (32 bytes base64 preferible).
- `NODE_ENV` — development/production.
- `LOG_LEVEL` — info/debug.

---

## 4. Migraciones y seed
- Migraciones: crear tablas `users`, `credentials`, `audit_logs`.
- Seed: usuarios de prueba (ejemplos abajo), credenciales de prueba para cada usuario.

---

## 5. Usuarios de prueba (para seed)
- Usuario 1: `alice@example.com` / `Password123!`
- Usuario 2: `bob@example.com` / `Password456!`

(En seed real, las contraseñas se guardan hasheadas con bcrypt.)

---

## 6. Cómo probar (manual)
1. Registrar usuario o usar usuario seed.
2. Login → recibir token/session.
3. Crear credencial → lista → detalle.
4. Mostrar contraseña → endpoint explícito que devuelve contraseña descifrada y registra `audit_logs`.
5. Editar / eliminar credencial.
6. Comprobar que un usuario no puede acceder a credenciales de otro.

---

## 7. Entregables del repositorio (estructura sugerida)
- `/backend` — backend (implementación opcional)
- `/frontend` — frontend (implementación opcional)
- `README.md` (este)
- `.env.example`
- `ERD.png` o `ERD.svg`
- `ARCHITECTURE.md` (diagrama y explicación)
- `API.md` (especificación de endpoints)
- `SEEDS.md` (datos de prueba)
- `EVALUATION.md` (criterios y casos de prueba)

---

## 8. Notas de seguridad
- Nunca guardar `ENCRYPTION_KEY` en repositorios.
- Políticas CORS y rate limiting recomendadas.
- Logs sensibles: no loguear contraseñas en texto plano.
