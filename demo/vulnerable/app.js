/**
 * API VULNERABLE — Demo OWASP
 *
 * Propósito:
 * Mostrar cómo se ve una API Node.js con vulnerabilidades reales.
 * Este archivo representa el estado ANTES de aplicar buenas prácticas de seguridad.
 *
 * Vulnerabilidades presentes:
 * - SQL Injection: los datos del usuario se insertan directamente en la query
 * - Cryptographic Failure: las contraseñas se comparan en texto plano
 * - Authentication Failure: los tokens JWT no tienen fecha de expiración
 * - Security Misconfiguration: los errores se exponen completos al cliente
 *
 * NO usar este código en producción.
 */

import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

// Clave secreta hardcodeada — nunca hacer esto en producción
const SECRET = 'clave_super_secreta_123';

// ─── Base de datos simulada en memoria ────────────────────────────────────────
// Representa una tabla "users" con contraseñas en TEXTO PLANO
// (Cryptographic Failure: A02)
const users = [
  { id: 1, username: 'admin', password: '1234', role: 'admin' },
  { id: 2, username: 'juan',  password: 'pass', role: 'user'  },
];

// ─── Función auxiliar: simula un query SQL vulnerable ─────────────────────────
// En un caso real esto iría contra PostgreSQL/MySQL.
// Aquí simulamos la lógica de concatenación directa para mostrar el problema.
function queryVulnerable(username, password) {
  // VULNERABILIDAD — SQL Injection (A03):
  // El username y password se insertan sin sanitizar en la "query".
  // Si el atacante manda username = ' OR '1'='1' --, entra sin contraseña.
  const fakeSQL = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  console.log('[SQL generado]:', fakeSQL);

  // Simulamos la ejecución: buscamos coincidencia directa (texto plano)
  return users.find(u => u.username === username && u.password === password) || null;
}

// ─── POST /login — Endpoint de autenticación vulnerable ───────────────────────
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Sin validación de entrada — cualquier cosa pasa directo a la "query"
  const user = queryVulnerable(username, password);

  if (!user) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // VULNERABILIDAD — Authentication Failure (A07):
  // El token no tiene fecha de expiración (expiresIn ausente).
  // Si alguien lo roba, es válido para siempre.
  const token = jwt.sign({ userId: user.id, role: user.role }, SECRET);

  res.json({ token });
});

// ─── GET /admin — Ruta protegida sin verificar el rol ─────────────────────────
app.get('/admin', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verifica el token, pero no controla si el usuario es admin
    const payload = jwt.verify(token, SECRET);

    // VULNERABILIDAD — Broken Access Control (A01):
    // Cualquier usuario con un token válido llega acá, sin importar su rol.
    res.json({ mensaje: 'Bienvenido al panel de administración', usuario: payload });
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ─── GET /users/:id — Endpoint vulnerable a IDOR ──────────────────────────────
app.get('/users/:id', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verifica el token pero NO compara con el id del token
    jwt.verify(token, SECRET);

    // VULNERABILIDAD — Broken Access Control / IDOR (A01):
    // Cualquier usuario logueado puede pedir los datos de CUALQUIER otro
    // usuario solo cambiando el :id en la URL.
    const user = users.find(u => u.id === parseInt(req.params.id));

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Devuelve la contraseña en texto plano — Cryptographic Failure (A02)
    res.json(user);
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ─── Manejo de errores — expone el stack trace completo ───────────────────────
// VULNERABILIDAD — Security Misconfiguration (A05):
// El mensaje de error detallado revela rutas internas, versiones y lógica del servidor.
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.stack });
});

// ─── Inicio del servidor ───────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`[VULNERABLE] Servidor corriendo en http://localhost:${PORT}`);
  console.log('Probá POST /login con { "username": "admin", "password": "1234" }');
});
