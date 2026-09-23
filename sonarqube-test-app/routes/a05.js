/**
 * ============================================================================
 *  ⚠️  OWASP A05:2025 — INJECTION  ⚠️
 * ============================================================================
 * Every route below is deliberately vulnerable, for training / SonarQube
 * SAST validation / manual DAST practice only. No login is required.
 * Reference: https://owasp.org/Top10/2025/A05_2025-Injection/
 * ============================================================================
 */

const express = require('express');
const { exec } = require('child_process');
const store = require('../data/injection-store');

const router = express.Router();

/* ------------------------------------------------------------------------
 * Variant 1: SQL Injection — Authentication Bypass — CWE-89
 *            (OWASP Example Attack Scenario #1, adapted to a login form)
 *   POST /api/a05/sql-login { username, password }
 *   The SQL query is built by direct string concatenation against a REAL
 *   embedded SQLite database (Node's built-in node:sqlite) — no
 *   parameterization, no escaping.
 * -------------------------------------------------------------------- */
router.post('/sql-login', (req, res) => {
  if (!store.sqlAvailable) return res.status(500).json({ error: 'node:sqlite is unavailable on this Node.js version (requires Node 22.5+).' });
  const { username = '', password = '' } = req.body || {};
  // VULNERABLE: raw string concatenation building the SQL statement.
  const query = `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const row = store.db.prepare(query).get();
    res.json({ query, authenticated: !!row, user: row || null });
  } catch (e) {
    res.status(400).json({ query, error: e.message });
  }
});

/* ------------------------------------------------------------------------
 * Variant 2: SQL Injection — UNION-Based Data Exfiltration — CWE-89
 *   GET /api/a05/search?q=ali
 *   A "search users" feature vulnerable to the same string-concatenation
 *   flaw — but here exploited with UNION SELECT to pull rows from a
 *   completely unrelated table (api_keys) that the endpoint was never
 *   meant to expose.
 * -------------------------------------------------------------------- */
router.get('/search', (req, res) => {
  if (!store.sqlAvailable) return res.status(500).json({ error: 'node:sqlite is unavailable on this Node.js version (requires Node 22.5+).' });
  const q = req.query.q || '';
  // VULNERABLE: same flaw, different shape — LIKE clause built by concatenation.
  const query = `SELECT username, role FROM users WHERE username LIKE '%${q}%'`;
  try {
    const rows = store.db.prepare(query).all();
    res.json({ query, rows });
  } catch (e) {
    res.status(400).json({ query, error: e.message });
  }
});

/* ------------------------------------------------------------------------
 * Variant 3: OS Command Injection — CWE-77 / CWE-78
 *            (OWASP Example Attack Scenario #3)
 *   GET /api/a05/ping?host=127.0.0.1
 *   User input is concatenated directly into a shell command string.
 * -------------------------------------------------------------------- */
router.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // VULNERABLE: unsanitized input concatenated into a shell command.
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ command: `ping -c 1 ${host}`, stdout, stderr, error: err ? err.message : null });
  });
});

/* ------------------------------------------------------------------------
 * Variant 4: Code Injection via eval() — CWE-94 / CWE-95
 *   POST /api/a05/calculate { expression }
 *   A "calculator" feature evaluates user input directly.
 * -------------------------------------------------------------------- */
router.post('/calculate', (req, res) => {
  const { expression } = req.body || {};
  try {
    // eslint-disable-next-line no-eval
    const result = eval(expression);
    res.json({ expression, result });
  } catch (e) {
    res.status(400).json({ expression, error: e.message });
  }
});

/* ------------------------------------------------------------------------
 * Variant 5: Reflected Cross-Site Scripting (XSS) — CWE-79
 *   GET /api/a05/greet?name=Guest
 *   User input is reflected directly into the HTML response with no
 *   escaping — open this URL directly in a browser tab (not via fetch)
 *   to see the injected script actually execute.
 * -------------------------------------------------------------------- */
router.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // VULNERABLE: unescaped user input reflected directly into HTML.
  res.send(`<html><body><h1>Hello, ${name}!</h1><p>Welcome to the A05 Injection lab.</p></body></html>`);
});

/* ------------------------------------------------------------------------
 * Variant 6: Stored Cross-Site Scripting (XSS) — CWE-79 / CWE-80
 *   POST /api/a05/comments { body }
 *   GET  /api/a05/comments
 *   Comment content is stored and later rendered back with no
 *   sanitization — every future visitor's browser executes it.
 * -------------------------------------------------------------------- */
router.post('/comments', (req, res) => {
  const { body } = req.body || {};
  store.comments.push(String(body || ''));
  res.json({ ok: true, totalComments: store.comments.length });
});

router.get('/comments', (req, res) => {
  // VULNERABLE: stored content rendered back without escaping.
  const html = store.comments.map((c) => `<div class="comment">${c}</div>`).join('') || '<p>No comments yet.</p>';
  res.send(`<html><body><h2>Comments</h2>${html}</body></html>`);
});

/* ------------------------------------------------------------------------
 * Variant 7: NoSQL Injection (Operator Injection) — CWE-943
 *            (implied by OWASP's own description, which names NoSQL
 *            alongside SQL/OS/ORM/LDAP/EL as a common injection target)
 *   POST /api/a05/nosql-login  (raw JSON body — send password as an
 *   object, not a string, to exploit this)
 * -------------------------------------------------------------------- */
router.post('/nosql-login', (req, res) => {
  const { username, password } = req.body || {};
  // VULNERABLE: whatever the client sends for `password` — string OR a
  // MongoDB-style operator object like {"$ne": null} — is passed straight
  // into the query with no type validation.
  const matches = store.noSqlFind(store.noSqlUsers, { username, password });
  res.json({ queryReceived: { username, password }, authenticated: matches.length > 0, user: matches[0] || null });
});

/* ------------------------------------------------------------------------
 * Variant 8: LDAP Injection — CWE-90
 *   GET /api/a05/ldap-search?uid=alice
 *   The uid parameter is spliced directly into an LDAP filter string
 *   with no escaping of ( ) * \ — the characters LDAP filter syntax
 *   requires to be neutralized.
 * -------------------------------------------------------------------- */
router.get('/ldap-search', (req, res) => {
  const uid = req.query.uid || '';
  try {
    const { filterStr, results } = store.ldapSearch(uid);
    res.json({ filter: filterStr, results });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ------------------------------------------------------------------------
 * Variant 9: XPath Injection — CWE-91 / CWE-643
 *   POST /api/a05/xpath-login { username, password }
 *   An XML-backed "login" lookup built by string concatenation into an
 *   XPath-style boolean expression.
 * -------------------------------------------------------------------- */
router.post('/xpath-login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const { expr, match } = store.xpathLogin(username, password);
  res.json({ expr, authenticated: !!match, user: match || null });
});

/* ------------------------------------------------------------------------
 * Variant 10: Server-Side Template Injection (SSTI) / Expression
 *             Language Injection — CWE-917 / CWE-94
 *   POST /api/a05/welcome { name }
 *   The user-supplied name becomes part of the TEMPLATE SOURCE itself
 *   (not just a substituted value), so embedding {{ ... }} in the input
 *   causes the template engine to evaluate it as code.
 * -------------------------------------------------------------------- */
router.post('/welcome', (req, res) => {
  const { name = 'Guest' } = req.body || {};
  // VULNERABLE: user input becomes part of the template SOURCE, not a
  // value substituted into it — that's what makes {{ }} in the input
  // reach the template evaluator.
  const template = `Hello, ${name}! Welcome back.`;
  const rendered = store.naiveTemplateRender(template, { name, require });
  res.json({ template, rendered });
});

/* ------------------------------------------------------------------------
 * Variant 11: Log / CRLF Injection (Log Forging) — CWE-93 / CWE-117
 *   POST /api/a05/log-event { username }
 *   GET  /api/a05/logs
 *   Note: Node's http module blocks raw CR/LF characters in actual HTTP
 *   header values (ERR_INVALID_CHAR) — a platform-level fix for classic
 *   HTTP response splitting. Application logs have no such protection,
 *   so this demonstrates the same unneutralized-newline flaw there
 *   instead: an attacker can forge fake log entries.
 * -------------------------------------------------------------------- */
router.post('/log-event', (req, res) => {
  const { username = '' } = req.body || {};
  // VULNERABLE: raw user input written into a log line with embedded
  // newlines left intact, letting the attacker inject fake extra "lines".
  store.logAudit(`[AUDIT] Login attempt for user: ${username}`);
  res.json({ ok: true });
});

router.get('/logs', (req, res) => {
  res.json({ lines: store.auditLog });
});

module.exports = router;
