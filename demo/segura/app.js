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
