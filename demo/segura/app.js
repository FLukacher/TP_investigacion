/**
 * API SEGURA — Demo OWASP
 *
 * Propósito:
 * Mostrar la misma API pero con las vulnerabilidades corregidas.
 * Este archivo representa el estado DESPUÉS de aplicar las medidas de seguridad
 * recomendadas por OWASP para un backend Node.js.
 *
 * Mejoras aplicadas:
 * - Queries parametrizados para prevenir SQL Injection
 * - bcrypt para hashear y comparar contraseñas de forma segura
 * - JWT con fecha de expiración
 * - helmet para proteger los headers HTTP
 * - rate limiting para prevenir ataques de fuerza bruta
 * - Mensajes de error genéricos en producción
 */

import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import 'dotenv/config';

const app = express();

// ─── helmet: agrega headers HTTP de seguridad automáticamente ─────────────────
// Previene ataques como clickjacking, XSS y sniffing de MIME type (A05).
app.use(helmet());
app.use(express.json());

// ─── Clave secreta desde variable de entorno ──────────────────────────────────
// Nunca hardcodear secretos en el código (A05 / A02).
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  console.error('ERROR: JWT_SECRET no está definida en .env');
  process.exit(1);
}

// ─── Base de datos simulada en memoria ────────────────────────────────────────
// Las contraseñas están hasheadas con bcrypt — Cryptographic Failure resuelto (A02).
// Los hashes corresponden a: admin → "1234", juan → "pass"
const users = [
  {
    id: 1,
    username: 'admin',
    // Hash generado con: bcrypt.hashSync('1234', 10)
    password: '$2b$10$KixwsD1bBSMq4F1Vf7EjAuJl8h8hHXhkUq7sVJbcHQv5MVOTHPXzO',
    role: 'admin',
  },
  {
    id: 2,
    username: 'juan',
    // Hash generado con: bcrypt.hashSync('pass', 10)
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    role: 'user',
  },
];

// ─── Función auxiliar: simula query parametrizado ─────────────────────────────
// FIX — SQL Injection (A03): el username no se concatena en la query,
// se busca con comparación estricta (como haría un prepared statement).
function querySeguro(username) {
  const fakeSQL = 'SELECT * FROM users WHERE username = $1';
  console.log('[SQL seguro]:', fakeSQL, '| param:', username);
  return users.find(u => u.username === username) || null;
}

// ─── Middleware: verificar JWT ─────────────────────────────────────────────────
// Reutilizable en cualquier ruta que requiera autenticación.
function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // FIX — Authentication Failure (A07): el token tiene expiración (1h),
    // por lo que si es robado, deja de ser válido en poco tiempo.
    const payload = jwt.verify(token, SECRET);
    req.user = payload; // guardamos el payload para usarlo en las rutas
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ─── Middleware: verificar rol de admin ───────────────────────────────────────
// FIX — Broken Access Control (A01): solo usuarios con role='admin' pasan.
function soloAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado: se requiere rol admin' });
  }
  next();
}

// ─── Rate limiter para el endpoint de login ───────────────────────────────────
// FIX — Authentication Failure / Insecure Design (A04, A07):
// Limita a 10 intentos cada 15 minutos para frenar ataques de fuerza bruta.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // ventana de 15 minutos
  max: 10,
  message: { error: 'Demasiados intentos. Intentá de nuevo en 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── POST /login — Endpoint de autenticación seguro ───────────────────────────
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  // Validación básica de entrada — nunca confiar en datos del usuario
  if (!username || !password) {
    return res.status(400).json({ error: 'username y password son requeridos' });
  }

  // FIX — SQL Injection (A03): usamos query parametrizado
  const user = querySeguro(username);

  // Mensaje genérico tanto para usuario inexistente como para contraseña incorrecta.
  // Así no se filtra qué dato está mal (enumeration attack).
  if (!user) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // FIX — Cryptographic Failure (A02): bcrypt.compare nunca expone la contraseña real
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // FIX — Authentication Failure (A07): token con expiración de 1 hora
  const token = jwt.sign({ userId: user.id, role: user.role }, SECRET, { expiresIn: '1h' });

  res.json({ token });
});

// ─── GET /admin — Ruta protegida con doble middleware ─────────────────────────
// FIX — Broken Access Control (A01): verificarToken + soloAdmin aseguran
// que solo un admin autenticado pueda acceder.
app.get('/admin', verificarToken, soloAdmin, (req, res) => {
  res.json({ mensaje: 'Bienvenido al panel de administración', usuario: req.user });
});

// ─── GET /users/:id — Endpoint con control de acceso por identidad ─────────────
app.get('/users/:id', verificarToken, (req, res) => {
  const requestedId = parseInt(req.params.id);

  // FIX — Broken Access Control / IDOR (A01):
  // Un usuario común solo puede ver sus propios datos.
  // Un admin puede ver cualquier perfil.
  if (req.user.role !== 'admin' && req.user.userId !== requestedId) {
    return res.status(403).json({ error: 'No podés acceder a datos de otro usuario' });
  }

  const user = users.find(u => u.id === requestedId);

  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  // FIX — Cryptographic Failure (A02): nunca devolver el hash de la contraseña
  const { password: _pass, ...safeUser } = user;
  res.json(safeUser);
});

// ─── Manejo de errores — mensaje genérico en producción ───────────────────────
// FIX — Security Misconfiguration (A05): el cliente nunca ve el stack trace.
// Solo se loguea internamente (donde debería ir a un sistema de logs centralizados).
app.use((err, req, res, _next) => {
  console.error('[Error interno]:', err); // log interno, no llega al cliente
  res.status(500).json({ error: 'Algo salió mal. Intentá más tarde.' });
});

// ─── Inicio del servidor ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`[SEGURA] Servidor corriendo en http://localhost:${PORT}`);
  console.log('Probá POST /login con { "username": "admin", "password": "1234" }');
});
