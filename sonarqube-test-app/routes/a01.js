/**
 * ============================================================================
 *  ⚠️  OWASP A01:2021 — BROKEN ACCESS CONTROL  ⚠️
 * ============================================================================
 * Every route below is deliberately vulnerable, for training / SonarQube
 * SAST validation / manual DAST practice only. Login first via POST /login
 * to get a token (also set as a cookie), then send it as:
 *   Authorization: Bearer <token>
 * The A01 screen's UI does this for you automatically.
 *
 * Demo accounts (see data/store.js):
 *   alice / alice123   — user,  tenant "Acme Corp"  (tenantId 1)
 *   bob   / bobpass    — user,  tenant "Globex Inc" (tenantId 2)
 *   admin / Admin@123  — admin, tenant "Acme Corp"  (tenantId 1)
 *   carol / carolpass  — user,  tenant "Globex Inc" (tenantId 2)
 *   mallory / mallorypass — user, tenant "Acme Corp" (attacker persona, 0 credits)
 * ============================================================================
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const store = require('../data/store');
const { issueToken, fakeAuth, requireAdmin } = require('../utils/auth');

const router = express.Router();

/* ------------------------------------------------------------------------
 * Login — issues the unsigned token described in utils/auth.js, both as a
 * JSON field (for API/Bearer use) and as a cookie (for the CSRF demo).
 * -------------------------------------------------------------------- */
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = store.findUserByUsername(username);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = issueToken({ id: user.id, username: user.username, role: user.role, tenantId: user.tenantId });

  // VULN (supports Variant 10 — CSRF): cookie has no SameSite attribute
  // and no CSRF token is ever required on state-changing requests that
  // rely on it, so a third-party site can trigger authenticated actions
  // simply by getting the victim's browser to hit the URL.
  res.cookie('a01_session', token, { httpOnly: false });

  res.json({ token, user: store.safeUser(user) });
});

router.post('/logout', (req, res) => {
  res.clearCookie('a01_session');
  res.json({ loggedOut: true });
});

/* ------------------------------------------------------------------------
 * Variant 6: JWT / Token Tampering — Trusting an Unsigned Client-Supplied
 *            Role Claim — CWE-347
 *   GET /api/a01/whoami
 *   Decode the token from /login (it's just base64 JSON, see utils/auth.js),
 *   change "role" to "admin" or "tenantId" to another tenant's id, base64
 *   re-encode, send it back as Authorization: Bearer <token>. This endpoint
 *   — and every other route in this file — will trust it completely.
 * -------------------------------------------------------------------- */
router.get('/whoami', fakeAuth, (req, res) => {
  res.json({ user: req.user });
});

/* ------------------------------------------------------------------------
 * Variant 1: Insecure Direct Object Reference (IDOR) /
 *            Horizontal Privilege Escalation — CWE-639
 *   GET /api/a01/orders/:id
 *   Log in as alice (order id 1) but request order id 2 (bob's order,
 *   different user, different tenant) -> returned anyway. There is no
 *   check that order.userId === req.user.id.
 * -------------------------------------------------------------------- */
router.get('/orders/:id', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const order = store.findOrderById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  // Vulnerable: no `order.userId === req.user.id` ownership check.
  res.json(order);
});

/* ------------------------------------------------------------------------
 * Variant 2: Vertical Privilege Escalation
 *            (Missing Function-Level Access Control) — CWE-862
 *   GET /api/a01/admin/users
 *   Any logged-in user — even plain "user" role — can call an endpoint
 *   that is clearly meant to be admin-only, because the route never
 *   applies requireAdmin.
 * -------------------------------------------------------------------- */
router.get('/admin/users', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  // Vulnerable: should be router.get('/admin/users', fakeAuth, requireAdmin, ...)
  // Also leaks password fields — bonus CWE-359 sensitive data exposure.
  res.json(store.users);
});

/* ------------------------------------------------------------------------
 * Variant 7: Forced Browsing to an Unprotected Admin Resource — CWE-425
 *   GET /api/a01/admin/stats
 *   Backs the "hidden" admin panel page (public/a01/admin-panel.html),
 *   which is reachable by anyone who guesses/finds the URL — there is no
 *   server-side session or role check at all on the page OR this API.
 *   Security relied entirely on the URL not being linked from the UI
 *   ("security through obscurity"), which is not access control.
 * -------------------------------------------------------------------- */
router.get('/admin/stats', (req, res) => {
  // Vulnerable: no fakeAuth, no requireAdmin — completely unauthenticated.
  res.json({
    totalUsers: store.users.length,
    totalOrders: store.orders.length,
    totalRevenue: store.orders.reduce((sum, o) => sum + o.amount, 0),
    allUsernamesAndRoles: store.users.map((u) => ({ username: u.username, role: u.role, tenantId: u.tenantId })),
  });
});

/* ------------------------------------------------------------------------
 * Variant 3: Mass Assignment / Parameter Tampering
 *            (Privilege Escalation via Payload) — CWE-915
 *   PUT /api/a01/users/:id/profile   { "bio": "hi", "role": "admin" }
 *   Meant to let a user edit their own bio/email, but blindly merges the
 *   entire request body onto the record — including fields like "role" or
 *   "tenantId" that a client should never be able to set directly.
 * -------------------------------------------------------------------- */
router.put('/users/:id/profile', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const user = store.findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });

  // Vulnerable: Object.assign with an un-filtered request body lets the
  // caller overwrite ANY field, e.g. { "role": "admin" } or
  // { "tenantId": 1 } — classic mass-assignment privilege escalation.
  // A safe version would whitelist only { bio, email }.
  Object.assign(user, req.body);

  res.json({ updated: true, user: store.safeUser(user) });
});

/* ------------------------------------------------------------------------
 * Variant 4: HTTP Verb / Method Tampering — CWE-650
 *   GET    /api/a01/admin/orders/:id   -> correctly protected by requireAdmin
 *   DELETE /api/a01/admin/orders/:id   -> same path, but the developer
 *                                         forgot requireAdmin here, so any
 *                                         caller (even unauthenticated) can
 *                                         delete an order just by
 *                                         switching the HTTP verb.
 * -------------------------------------------------------------------- */
router.get('/admin/orders/:id', fakeAuth, requireAdmin, (req, res) => {
  const order = store.findOrderById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});

router.delete('/admin/orders/:id', fakeAuth, (req, res) => {
  // Vulnerable: requireAdmin is missing on this verb even though GET on
  // the identical path enforces it — attacker just sends DELETE instead.
  const deleted = store.deleteOrder(req.params.id);
  res.json({ deleted });
});

/* ------------------------------------------------------------------------
 * Variant 5: Multi-Tenant Data Leakage (Tenant Isolation Bypass) — CWE-668
 *   GET /api/a01/tenants/:tenantId/orders
 *   Logged in as a tenant-2 user (bob/carol) but request tenantId=1 in
 *   the URL -> tenant 1's (Acme Corp's) orders are returned anyway.
 * -------------------------------------------------------------------- */
router.get('/tenants/:tenantId/orders', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  // Vulnerable: trusts the :tenantId path param instead of enforcing
  // req.user.tenantId === req.params.tenantId, so any tenant can read
  // any other tenant's data just by changing the URL.
  res.json(store.ordersByTenant(req.params.tenantId));
});

/* ------------------------------------------------------------------------
 * Variant 8: Client-Side-Only Access Control
 *            (Enforcement Lives Only in the UI) — CWE-602
 *   DELETE /api/a01/orders/:id/force
 *   The dashboard hides the "force delete" button unless the logged-in
 *   user's (client-side-decoded) role is "admin" — a pure JS/UI check —
 *   but the backend route performs NO authorization check at all, so the
 *   restriction is cosmetic and trivially bypassed with curl/Postman.
 * -------------------------------------------------------------------- */
router.delete('/orders/:id/force', (req, res) => {
  // Vulnerable: no fakeAuth, no requireAdmin, no check of any kind —
  // access control exists only as a hidden button in public/a01/a01.js.
  const deleted = store.deleteOrder(req.params.id);
  res.json({ deleted });
});

/* ------------------------------------------------------------------------
 * Variant 9: CORS Misconfiguration Enabling Cross-Origin
 *            Credentialed Access — CWE-942
 *   GET /api/a01/account
 *   The whole app is served behind `cors({ origin: true, credentials:
 *   true })` (see server.js) — meaning it reflects back whatever Origin
 *   header the caller sends AND allows credentials. A page hosted on
 *   *any* other domain can issue a fetch() with credentials:'include'
 *   against this endpoint and read the logged-in user's sensitive data,
 *   using nothing but the victim's browser session/cookie.
 * -------------------------------------------------------------------- */
router.get('/account', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const user = store.findUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  // Vulnerable: sensitive account data served to any origin thanks to the
  // permissive CORS policy configured in server.js.
  res.json(store.safeUser(user));
});

/* ------------------------------------------------------------------------
 * Variant 10: Cross-Site Request Forgery (CSRF) — CWE-352
 *   GET /api/a01/transfer?to=mallory&amount=50
 *   State-changing action (moving "credits" between accounts) that:
 *     (a) is wired up on GET instead of POST (itself an anti-pattern —
 *         browsers will send GET requests for <img>, <link>, simple
 *         navigations, etc. with zero user interaction), and
 *     (b) relies solely on the a01_session cookie for "auth", with no
 *         CSRF token, no Origin/Referer check, and no SameSite
 *         restriction on the cookie (see /login above).
 *   See public/a01/csrf-poc.html for a simulated malicious page that
 *   exploits this against a logged-in victim.
 * -------------------------------------------------------------------- */
router.get('/transfer', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const { to, amount } = req.query;
  const amt = Number(amount);
  const sender = store.findUserById(req.user.id);
  const recipient = store.findUserByUsername(to);
  if (!recipient) return res.status(404).json({ error: 'Recipient not found' });
  if (!amt || amt <= 0 || sender.credits < amt) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  // Vulnerable: no CSRF token verification, no re-authentication for a
  // sensitive action, and the action is state-changing on a GET route.
  sender.credits -= amt;
  recipient.credits += amt;
  res.json({ transferred: amt, from: sender.username, to: recipient.username, senderBalance: sender.credits });
});

/* ------------------------------------------------------------------------
 * Variant 11: Path Traversal Bypassing Access Restriction on Files
 *             — CWE-22 / CWE-23
 *             (Officially mapped under A01:2021 in OWASP's Top 10 CWE list)
 *   GET /api/a01/files?tenant=tenant-1&name=invoice.txt
 *   Meant to let a logged-in user read only their own tenant's invoice
 *   folder (private/<tenant>/), but the "name" parameter is joined onto
 *   the path with no normalisation or allow-list check, so:
 *     ?tenant=tenant-2&name=invoice.txt        -> reads the OTHER tenant's file
 *     ?tenant=tenant-1&name=../../secrets.txt  -> escapes private/ entirely
 *   There is also no check that req.user.tenantId matches the requested
 *   :tenant — a second, independent access-control bug layered on top of
 *   the path traversal.
 * -------------------------------------------------------------------- */
router.get('/files', fakeAuth, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const { tenant, name } = req.query;
  // Vulnerable: neither `tenant` nor `name` is validated against an
  // allow-list, and there's no check that `tenant` matches req.user.tenantId.
  const filePath = path.join(__dirname, '..', 'private', tenant || '', name || 'invoice.txt');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: err.message, filePath });
    res.type('text/plain').send(data);
  });
});

module.exports = router;
