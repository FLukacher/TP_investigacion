
CHAT GPT - PLAN DE ORGANIZACIÓN DEL TP: https://docs.google.com/document/d/1lSbQW4qfQpkE6CeRiqek4Faf3gioeqAhfoI6BaO1VHw/edit?usp=sharing

# OWASP aplicado a APIs Node.js

> **Problemática:** Una auditoría de seguridad encontró varias vulnerabilidades en nuestra API.

---

## ¿Qué es OWASP?

**OWASP** (Open Web Application Security Project) es una organización sin fines de lucro dedicada a mejorar la seguridad del software. Publican guías, herramientas y listas de vulnerabilidades comunes, todo de forma **gratuita y abierta**.

Es la referencia más usada en el mundo cuando se habla de seguridad web.

---

## ¿Qué es OWASP Top 10?

Es una lista con las **10 vulnerabilidades más peligrosas y frecuentes** en aplicaciones web. Se actualiza cada ciertos años (la última es de **2021**).

Es básicamente un *"top 10 de cosas que no podés ignorar si querés que tu app sea segura"*.

---

## Principales Vulnerabilidades (Top 10 – 2021)

**1. Broken Access Control**
Un usuario logueado puede acceder a datos o acciones que no le corresponden. Por ejemplo, un usuario común que puede ver la información de otro simplemente cambiando un número en la URL (`/users/123` → `/users/124`), o acceder a rutas de administrador sin ser admin.
**2. Cryptographic Failures**
La app maneja datos sensibles (contraseñas, tarjetas, tokens) sin la protección adecuada. Puede ser que los guarde en texto plano en la base de datos, que los mande por HTTP sin cifrar, o que use algoritmos viejos y débiles como MD5. Si alguien roba la base de datos, tiene todo.
**3. Injection**
El atacante manda datos maliciosos en un campo de texto (login, buscador, formulario) y la app los ejecuta como si fueran código. El caso más clásico es SQL Injection: meter `' OR '1'='1'` en el campo de usuario para entrar sin contraseña. También existe en NoSQL, comandos del sistema, etc.
**4. Insecure Design**
El problema no está en el código en sí, sino en cómo se pensó la app desde el principio. Por ejemplo, una app que no tiene límite de intentos de login por diseño, o que guarda información sensible que directamente no debería guardar. No se arregla con un parche, hay que rediseñar.
**5. Security Misconfiguration**
La app está corriendo con una configuración insegura. Ejemplos típicos: dejar el modo debug activo en producción (muestra errores detallados con rutas internas), tener CORS abierto para cualquier dominio, usar contraseñas por defecto en bases de datos, o exponer puertos que no deberían estar abiertos.
**6. Vulnerable Components**
La app usa librerías o paquetes de terceros que tienen vulnerabilidades conocidas y no fueron actualizados. En Node.js esto es muy común dado el ecosistema enorme de npm. Un paquete desactualizado puede tener un bug público que cualquier atacante puede explotar.
**7. Authentication Failures**
Fallas en el mecanismo que verifica quién sos. Puede ser un JWT sin fecha de expiración (si te lo roban, sirve para siempre), no tener límite de intentos de login (permite ataques de fuerza bruta), permitir contraseñas débiles, o no invalidar la sesión al cerrarla.
**8. Integrity Failures**
La app descarga o ejecuta código/datos sin verificar que sean legítimos. Por ejemplo, instalar un paquete npm malicioso que tiene un nombre muy parecido a uno popular (typosquatting), o una app que aplica actualizaciones automáticas sin verificar la firma digital de quien las mandó.
**9. Logging Failures**
La app no registra lo que pasa. Si alguien está intentando entrar por fuerza bruta, explorando rutas o explotando una vulnerabilidad, no hay forma de detectarlo ni de investigarlo después. Sin logs, los ataques pasan desapercibidos y no se puede hacer nada al respecto.
**10. SSRF (Server-Side Request Forgery)**
El atacante logra que el servidor haga una petición HTTP a una dirección que él elige. Por ejemplo, si la app tiene una función que recibe una URL y la consulta, el atacante puede mandar `http://169.254.169.254` (la IP interna de metadatos en servidores cloud) y obtener credenciales del servidor. El servidor hace el trabajo sucio desde adentro.

## ¿Cómo afectan a un backend Node.js?

Node.js es muy usado para construir APIs, por eso es un blanco frecuente. Puntos clave:

- **npm tiene miles de paquetes**, y cualquiera puede tener vulnerabilidades ocultas.
- **JavaScript es muy flexible**, pero esa flexibilidad facilita errores si no se valida bien la entrada del usuario.
- **Express no trae seguridad por defecto**, hay que configurarla manualmente.
- Si no se maneja bien la autenticación con JWT, **cualquiera puede hacerse pasar por otro usuario**.

---

## Medidas de Prevención Generales

- **Nunca confiar en los datos del usuario** → siempre validarlos y sanitizarlos.
- **Usar HTTPS siempre** → nunca exponer la API por HTTP en producción.
- **Guardar contraseñas con `bcrypt`** → nunca en texto plano.
- **Mantener paquetes actualizados** → correr `npm audit` seguido.
- **Usar `helmet`** en Express para proteger los headers HTTP.
- **Implementar rate limiting** → limitar cuántas peticiones puede hacer un usuario por minuto.

---

## Vulnerabilidades en Detalle

---

### 1. Injection

**¿Qué es?**
El atacante mete código malicioso dentro de un campo de texto (como el login), y ese código termina ejecutándose en la base de datos.

**Código vulnerable:**
```js
// El usuario manda: username = ' OR '1'='1' --
const query = `SELECT * FROM users WHERE username='${username}'`;
// Resultado: devuelve todos los usuarios, el atacante entra sin contraseña
```

**Solución — Query parametrizado:**
```js
// Los datos del usuario NUNCA se mezclan con el código SQL
db.query('SELECT * FROM users WHERE username = $1', [username]);
```

---

### 2. Broken Access Control

**¿Qué es?**
Un usuario puede hacer cosas para las que **no tiene permiso**. Por ejemplo, un usuario común puede borrar la cuenta de otro o acceder al panel de admin.

**Código vulnerable:**
```js
// Cualquier usuario logueado puede borrar a quien quiera
app.delete('/users/:id', isLoggedIn, (req, res) => {
  deleteUser(req.params.id); // No verifica si es admin
});
```

**Solución — Verificar el rol en cada ruta sensible:**
```js
app.delete('/users/:id', isLoggedIn, isAdmin, (req, res) => {
  deleteUser(req.params.id);
});
```

---

### 3. Authentication Failures

**¿Qué es?**
Fallas en cómo se maneja el login o los tokens. Ejemplos comunes: tokens sin fecha de vencimiento, contraseñas débiles permitidas, sin límite de intentos de login.

**Código vulnerable:**
```js
// Token eterno: si lo roban, sirve para siempre
jwt.sign({ userId: 1 }, SECRET);
```

**✅ Solución — Token con expiración + bcrypt:**
```js
// Token que expira en 1 hora
jwt.sign({ userId: 1 }, SECRET, { expiresIn: '1h' });

// Contraseña hasheada, nunca en texto plano
user.password = await bcrypt.hash(req.body.password, 10);
```

---

### 4. Security Misconfiguration

**¿Qué es?**
La app está mal configurada: muestra errores detallados en producción, tiene CORS abierto para cualquiera, o usa credenciales por defecto. Eso le da información valiosa al atacante.

**Código vulnerable:**
```js
// Muestra el stack trace completo con rutas internas y versiones de librerías
app.use((err, req, res, next) => res.json({ error: err.stack }));
```

**✅ Solución — Mensaje genérico en producción:**
```js
app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Algo salió mal' });
});
```

---

### 5. Cryptographic Failures

**¿Qué es?**
Datos sensibles que viajan o se guardan **sin la protección adecuada**. El caso más común: guardar contraseñas en texto plano o usar algoritmos viejos como MD5.

**Código vulnerable:**
```js
// La contraseña se guarda tal cual en la base de datos
user.password = req.body.password;
```

**Solución — Hashear con bcrypt:**
```js
// Si la base de datos es robada, las contraseñas no se pueden leer
user.password = await bcrypt.hash(req.body.password, 10);
```

---

## Desafío Técnico: Vulnerabilidad Real y su Solución

**Situación:** una API de login construida con Node.js + PostgreSQL.

### Código Vulnerable

```js
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // PROBLEMA 1: SQL Injection — los datos del usuario se meten directo en el query
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const result = await db.query(query);

  // PROBLEMA 2: la contraseña se compara en texto plano
  if (result.rows.length > 0) {
    res.json({ token: generateToken(result.rows[0]) });
  } else {
    res.status(401).json({ error: 'Credenciales inválidas' });
  }
});
```

**¿Qué puede hacer el atacante?**
Mandar `username = ' OR '1'='1' --` y entrar a la app **sin saber ninguna contraseña**.

---

### Código Corregido

```js
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // FIX 1: Query parametrizado — los datos nunca se mezclan con el SQL
  const result = await db.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );

  if (!result.rows[0]) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // FIX 2: Comparación segura con bcrypt
  const match = await bcrypt.compare(password, result.rows[0].password);
  if (!match) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  res.json({ token: generateToken(result.rows[0]) });
});
```

**Con estos dos cambios se eliminan la SQL Injection y el fallo criptográfico al mismo tiempo.**

---

## Referencias

- [OWASP Top 10 – 2021](https://owasp.org/Top10/)
- [helmet.js – Seguridad para Express](https://helmetjs.github.io/)
- [bcrypt para Node.js](https://www.npmjs.com/package/bcrypt)
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit)



