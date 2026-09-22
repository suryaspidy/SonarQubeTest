/**
 * ============================================================================
 *  ⚠️  INTENTIONALLY VULNERABLE APPLICATION  ⚠️
 * ============================================================================
 *  Purpose : Test bed for validating SonarQube (SAST) findings, and for
 *            exercising DAST scanners (e.g. OWASP ZAP) / IAST agents
 *            (e.g. Contrast, Seeker) against a running instance.
 *
 *  DO NOT deploy this application to production, a shared network, or the
 *  public internet. It contains deliberate security flaws by design.
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------------------------------------------------------------------- *
 * VULN: CWE-798 Use of Hard-coded Credentials / Secrets            (SAST) *
 * ---------------------------------------------------------------------- */
const JWT_SECRET = 'supersecretkey123';
const DB_ADMIN_USER = 'admin';
const DB_ADMIN_PASS = 'Admin@123';

/* ---------------------------------------------------------------------- *
 * VULN: CWE-942 Permissive Cross-Origin Resource Sharing            (SAST)*
 * ---------------------------------------------------------------------- */
app.use(cors({ origin: '*', credentials: true }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* No helmet / no security headers configured on purpose
 * -> VULN: CWE-693 Missing security headers (X-Frame-Options, CSP, HSTS) */

/* ------------------------------ Data layer ------------------------------ */
const db = new sqlite3.Database(':memory:');

function md5(input) {
  // VULN: CWE-327 Use of a Broken/Risky Cryptographic Algorithm (SAST)
  return crypto.createHash('md5').update(input).digest('hex');
}

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT,
    tenant_id INTEGER
  )`);

  // tenant_id groups users into separate "organizations" — used to
  // demonstrate multi-tenant data leakage below.
  const seedUsers = [
    [1, 'alice', md5('alice123'), 'alice@example.com', 'user', 1],
    [2, 'bob', md5('bobpass'), 'bob@example.com', 'user', 2],
    [3, 'admin', md5('Admin@123'), 'admin@example.com', 'admin', 1],
    [4, 'carol', md5('carolpass'), 'carol@example.com', 'user', 2],
  ];
  const stmt = db.prepare('INSERT INTO users VALUES (?,?,?,?,?,?)');
  seedUsers.forEach((u) => stmt.run(u));
  stmt.finalize();

  db.run(`CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)`);

  db.run(`CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    tenant_id INTEGER,
    item TEXT,
    amount REAL,
    notes TEXT
  )`);

  const seedOrders = [
    [1, 1, 1, 'Laptop', 1200, 'Card ending 4242 — alice, tenant 1'],
    [2, 2, 2, 'Phone', 800, 'Card ending 1234 — bob, tenant 2'],
    [3, 3, 1, 'Server rack', 5000, 'Internal PO#552 — admin, tenant 1'],
    [4, 4, 2, 'Monitor', 300, 'Card ending 9876 — carol, tenant 2'],
  ];
  const orderStmt = db.prepare('INSERT INTO orders VALUES (?,?,?,?,?,?)');
  seedOrders.forEach((o) => orderStmt.run(o));
  orderStmt.finalize();
});

/* ---------------------------------------------------------------------- *
 * "Auth" layer used by the Broken Access Control section below.
 *
 * VULN: CWE-347 Improper Verification of Cryptographic Signature.
 * The token is just base64(JSON) with NO signature — anyone can decode
 * it, edit the role/tenantId fields, re-encode, and present it back as
 * if it were still valid. This is what makes several of the variants
 * below exploitable, and is itself a common real-world flaw (trusting
 * an unsigned or unverified JWT-like token).
 * ---------------------------------------------------------------------- */
function issueToken(payload) {
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function decodeToken(token) {
  try {
    return JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

// Vulnerable "auth" middleware: trusts whatever role/tenantId/id is
// embedded in the client-supplied token, with no signature check and
// no re-verification against the database.
function fakeAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  req.user = token ? decodeToken(token) : null;
  next();
}

// Correct-looking helper that several routes below simply forget to use
// — that omission IS the vulnerability (missing function-level access
// control / verb tampering).
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin role required' });
  }
  next();
}

app.use(fakeAuth);

/* ========================================================================
 * 1. SQL INJECTION — CWE-89                              (SAST + DAST)
 *    GET /search?q=alice
 *    Try:  /search?q=' OR '1'='1
 * ==================================================================== */
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Vulnerable: string concatenation instead of a parameterised query
  const query = `SELECT id, username, email, role FROM users WHERE username = '${q}'`;
  db.all(query, (err, rows) => {
    if (err) {
      // VULN: CWE-209 Information Exposure Through an Error Message
      return res.status(500).json({ error: err.message, query });
    }
    res.json(rows);
  });
});

/* ========================================================================
 * 2. REFLECTED XSS — CWE-79                               (SAST + DAST)
 *    GET /greet?name=<script>alert(1)</script>
 * ==================================================================== */
app.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // Vulnerable: unescaped user input reflected directly into HTML
  res.send(`<h1>Hello, ${name}!</h1><p>Welcome to the SonarQube test app.</p>`);
});

/* ========================================================================
 * 3. STORED XSS — CWE-79                                  (SAST + DAST)
 *    POST /comments { "body": "<img src=x onerror=alert(1)>" }
 *    GET  /comments
 * ==================================================================== */
app.post('/comments', (req, res) => {
  const body = req.body.body || '';
  db.run('INSERT INTO comments (body) VALUES (?)', [body], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
});

app.get('/comments', (req, res) => {
  db.all('SELECT * FROM comments', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    // Vulnerable: stored content rendered back without sanitisation/escaping
    const html = rows.map((r) => `<div class="comment">${r.body}</div>`).join('');
    res.send(`<html><body><h2>Comments</h2>${html}</body></html>`);
  });
});

/* ========================================================================
 * 4. OS COMMAND INJECTION — CWE-78                        (SAST + DAST)
 *    GET /ping?host=127.0.0.1
 *    Try:  /ping?host=127.0.0.1;cat /etc/passwd
 * ==================================================================== */
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  // Vulnerable: unsanitised user input concatenated into a shell command
  exec(`ping -c 2 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: err.message, stderr });
    res.type('text/plain').send(stdout);
  });
});

/* ========================================================================
 * 5. PATH TRAVERSAL — CWE-22                              (SAST + DAST)
 *    GET /file?name=notes.txt
 *    Try:  /file?name=../../../../etc/passwd
 * ==================================================================== */
app.get('/file', (req, res) => {
  const name = req.query.name || 'notes.txt';
  // Vulnerable: no normalisation / allow-list check on the resolved path
  const filePath = path.join(__dirname, 'files', name);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: err.message, filePath });
    res.type('text/plain').send(data);
  });
});

/* ========================================================================
 * 6. BROKEN AUTH / HARD-CODED BACKDOOR — CWE-798, CWE-327, CWE-532 (SAST)
 *    POST /login { "username": "admin", "password": "Admin@123" }
 * ==================================================================== */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // VULN: CWE-532 Insertion of Sensitive Information into Log File
  console.log(`Login attempt: user=${username} pass=${password}`);

  // VULN: hard-coded backdoor credential check
  if (username === DB_ADMIN_USER && password === DB_ADMIN_PASS) {
    return res.json({
      token: issueToken({ id: 3, username: 'admin', role: 'admin', tenantId: 1 }),
      role: 'admin',
    });
  }

  const hashed = md5(password); // weak hash, see above
  db.get(
    `SELECT * FROM users WHERE username = '${username}' AND password = '${hashed}'`,
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: 'Invalid credentials' });
      // Token payload is fully trusted by later requests — see fakeAuth/
      // decodeToken above. Nothing stops a client from decoding this,
      // changing "role" to "admin" or "tenantId" to another tenant's id,
      // and re-encoding it.
      res.json({
        token: issueToken({ id: row.id, username: row.username, role: row.role, tenantId: row.tenant_id }),
        role: row.role,
      });
    }
  );
});

/* ========================================================================
 * 7. INSECURE DIRECT OBJECT REFERENCE (IDOR) — CWE-639          (DAST)
 *    GET /profile/1   (try /profile/2, /profile/3 with no auth token)
 * ==================================================================== */
app.get('/profile/:id', (req, res) => {
  // Vulnerable: no authentication/ownership check before returning the record
  db.get(
    'SELECT id, username, email, role FROM users WHERE id = ?',
    [req.params.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'Not found' });
      res.json(row);
    }
  );
});

/* ========================================================================
 * 8. OPEN REDIRECT — CWE-601                                    (DAST)
 *    GET /redirect?url=https://example.com
 * ==================================================================== */
app.get('/redirect', (req, res) => {
  const url = req.query.url || '/';
  // Vulnerable: redirect target is not validated against an allow-list
  res.redirect(url);
});

/* ========================================================================
 * 9. SERVER-SIDE REQUEST FORGERY (SSRF) — CWE-918         (SAST + DAST)
 *    GET /fetch?url=http://example.com
 * ==================================================================== */
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  try {
    // Vulnerable: server fetches an attacker-supplied URL, including
    // internal-network or cloud-metadata endpoints (e.g. 169.254.169.254)
    const r = await fetch(url);
    const text = await r.text();
    res.type('text/plain').send(text.slice(0, 2000));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ========================================================================
 * 10. CODE INJECTION via eval() — CWE-95                        (SAST)
 *     POST /calculate { "expression": "2+2" }
 *     Try:  { "expression": "require('child_process').execSync('id')" }
 * ==================================================================== */
app.post('/calculate', (req, res) => {
  const { expression } = req.body;
  try {
    // Vulnerable: eval() executed directly on user-controlled input
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ========================================================================
 * 11. INFORMATION DISCLOSURE / DEBUG ENDPOINT — CWE-215         (DAST)
 *     GET /debug
 * ==================================================================== */
app.get('/debug', (req, res) => {
  // Vulnerable: exposes environment variables, secrets and internal config
  res.json({
    env: process.env,
    jwtSecret: JWT_SECRET,
    adminCreds: { user: DB_ADMIN_USER, pass: DB_ADMIN_PASS },
    node: process.version,
    cwd: process.cwd(),
  });
});

/* ========================================================================
 * 12. INSECURE DESERIALIZATION — CWE-502                        (SAST)
 *     POST /import { "data": "{a:1}" }
 * ==================================================================== */
app.post('/import', (req, res) => {
  const { data } = req.body;
  try {
    // Vulnerable: Function constructor evaluates attacker-controlled data as code
    const obj = new Function('return ' + data)();
    res.json({ imported: obj });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ========================================================================
 * OWASP A01:2021 — BROKEN ACCESS CONTROL
 * ------------------------------------------------------------------------
 * Login first to get a token, then send it as:
 *   Authorization: Bearer <token>
 * The dashboard's "Broken Access Control" panel does this for you.
 * ==================================================================== */

/* ------------------------------------------------------------------------
 * Variant 1: IDOR / Horizontal Privilege Escalation — CWE-639
 *   GET /api/orders/:id
 *   Logged in as alice (user id 1) but request order id 2 (bob's order)
 *   -> returned anyway, no ownership check against req.user.id.
 * -------------------------------------------------------------------- */
app.get('/api/orders/:id', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  // Vulnerable: fetches the order by id only — never checks
  // order.user_id === req.user.id, so any authenticated user can read
  // any other user's order just by changing the id in the URL.
  db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

/* ------------------------------------------------------------------------
 * Variant 2: Vertical Privilege Escalation
 *            (Missing Function-Level Access Control) — CWE-862
 *   GET /api/admin/users
 *   Any logged-in user (even a plain "user" role) can call an endpoint
 *   that is clearly meant to be admin-only, because the route never
 *   applies requireAdmin.
 * -------------------------------------------------------------------- */
app.get('/api/admin/users', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  // Vulnerable: no requireAdmin check here — should be
  // app.get('/api/admin/users', fakeAuth, requireAdmin, ...)
  db.all('SELECT id, username, email, role, tenant_id, password FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows); // also leaks password hashes — bonus CWE-359 data exposure
  });
});

/* ------------------------------------------------------------------------
 * Variant 3: Mass Assignment / Parameter Tampering
 *            (Privilege Escalation via Payload) — CWE-915
 *   PUT /api/users/:id/profile   { "bio": "hi", "role": "admin" }
 *   The endpoint is meant to let a user edit their own bio/email, but it
 *   blindly merges the entire request body onto the DB row — including
 *   fields like "role" or "tenant_id" that the client should never be
 *   able to set directly.
 * -------------------------------------------------------------------- */
app.put('/api/users/:id/profile', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'Not found' });

    // Vulnerable: Object.assign with an un-filtered request body lets
    // the caller overwrite ANY column, e.g. { "role": "admin" } or
    // { "tenant_id": 1 } — classic mass-assignment privilege escalation.
    const updated = Object.assign(user, req.body);

    db.run(
      'UPDATE users SET username=?, password=?, email=?, role=?, tenant_id=? WHERE id=?',
      [updated.username, updated.password, updated.email, updated.role, updated.tenant_id, updated.id],
      (updateErr) => {
        if (updateErr) return res.status(500).json({ error: updateErr.message });
        res.json({ updated: true, user: updated });
      }
    );
  });
});

/* ------------------------------------------------------------------------
 * Variant 4: HTTP Verb / Method Tampering — CWE-650
 *   GET    /api/admin/orders/:id   -> correctly protected by requireAdmin
 *   DELETE /api/admin/orders/:id   -> same path, but the developer forgot
 *                                     to apply requireAdmin here, so any
 *                                     caller (even unauthenticated) can
 *                                     delete an order just by switching
 *                                     the HTTP verb.
 * -------------------------------------------------------------------- */
app.get('/api/admin/orders/:id', fakeAuth, requireAdmin, (req, res) => {
  db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.delete('/api/admin/orders/:id', fakeAuth, (req, res) => {
  // Vulnerable: requireAdmin is missing on this verb even though the
  // GET on the identical path enforces it — a classic method-tampering
  // bypass (attacker just sends DELETE instead of GET).
  db.run('DELETE FROM orders WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes > 0 });
  });
});

/* ------------------------------------------------------------------------
 * Variant 5: Multi-Tenant Data Leakage (Tenant Isolation Bypass) — CWE-668
 *   GET /api/tenants/:tenantId/orders
 *   Logged in as a tenant-2 user but request tenantId=1 in the URL
 *   -> tenant 1's orders are returned anyway.
 * -------------------------------------------------------------------- */
app.get('/api/tenants/:tenantId/orders', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  // Vulnerable: trusts the :tenantId path param instead of enforcing
  // req.user.tenantId === req.params.tenantId, so any tenant can read
  // any other tenant's data just by changing the URL.
  db.all('SELECT * FROM orders WHERE tenant_id = ?', [req.params.tenantId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

/* ------------------------------------------------------------------------
 * Variant 6: JWT / Token Tampering
 *            (Trusting a Client-Supplied, Unsigned Role Claim) — CWE-347
 *   GET /api/whoami
 *   The token issued by /login is just base64(JSON) with no signature
 *   (see issueToken/decodeToken above). Decode it, change "role" to
 *   "admin" or "tenantId" to another tenant, re-encode as base64, send
 *   it back as the Bearer token — the server accepts it as-is and every
 *   other endpoint in this section will now treat you as that identity.
 * -------------------------------------------------------------------- */
app.get('/api/whoami', fakeAuth, (req, res) => {
  // Vulnerable: simply echoes back whatever the (unverified) token said,
  // proving the server never re-validated it against a real session
  // store or a cryptographic signature.
  res.json({ user: req.user });
});

/* ------------------------------------------------------------------------
 * Variant 7: Forced Browsing to an Unprotected Admin Resource — CWE-425
 *   GET /admin.html   — served as a plain static file by express.static,
 *   with a real-looking admin panel UI, but with ZERO server-side check
 *   that the requester is logged in or an admin. Security relied on
 *   nobody guessing/finding the URL ("security through obscurity"),
 *   which is not access control.
 * -------------------------------------------------------------------- */
// (no route needed — public/admin.html is already reachable via the
//  express.static() middleware registered near the top of this file)

/* ------------------------------------------------------------------------
 * Variant 8: Client-Side-Only Access Control
 *            (Enforcement Lives Only in the UI) — CWE-602
 *   DELETE /api/orders/:id/force
 *   The dashboard hides the "force delete" button unless the logged-in
 *   user's role is "admin" (a pure JS/UI check) — but the backend route
 *   itself performs NO authorization check at all, so the restriction
 *   is cosmetic and trivially bypassed with curl/Postman.
 * -------------------------------------------------------------------- */
app.delete('/api/orders/:id/force', (req, res) => {
  // Vulnerable: no fakeAuth, no requireAdmin, no check of any kind —
  // access control exists only as a hidden button in public/app.js.
  db.run('DELETE FROM orders WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes > 0 });
  });
});

/* Generic error handler that leaks stack traces — CWE-209 */
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

app.listen(PORT, () => {
  console.log(`Vulnerable test app running at http://localhost:${PORT}`);
  console.log('WARNING: do not expose this server to an untrusted network.');
});
