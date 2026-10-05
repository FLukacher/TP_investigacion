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
