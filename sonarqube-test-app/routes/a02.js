/**
 * ============================================================================
 *  ⚠️  OWASP A02:2021 — CRYPTOGRAPHIC FAILURES  ⚠️
 * ============================================================================
 * Every route below is deliberately vulnerable, for training / SonarQube
 * SAST validation / manual DAST practice only. Nothing here requires
 * logging in — cryptographic failures are about how data is stored,
 * transmitted, and transformed, not who's allowed to ask for it (that's
 * A01). See data/crypto-store.js for the underlying (intentionally weak)
 * crypto helpers and seed data.
 * ============================================================================
 */

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const store = require('../data/crypto-store');

const router = express.Router();

/* ------------------------------------------------------------------------
 * Variant 1: Cleartext Storage of Sensitive Data at Rest — CWE-312/CWE-313
 *   GET /api/a02/payment-methods
 *   Full card numbers and CVVs stored and returned as plain strings —
 *   exactly what a stolen database backup or an over-privileged internal
 *   tool would expose. CVVs in particular should never be stored at all
 *   (PCI-DSS forbids persisting them post-authorization).
 * -------------------------------------------------------------------- */
router.get('/payment-methods', (req, res) => {
  // Vulnerable: no masking (e.g. "**** **** **** 1111"), no field-level
  // encryption, no access control — a raw dump of sensitive financial data.
  res.json(store.paymentMethods);
});

/* ------------------------------------------------------------------------
 * Variant 2: Weak / Broken Hashing Algorithm for Passwords — CWE-327/CWE-759
 *   GET  /api/a02/weak-hash-users
 *   POST /api/a02/crack-hash { hash }
 *   Passwords are hashed with unsalted MD5 — fast and collision-prone,
 *   with no per-user salt. A handful of common passwords crack it instantly.
 * -------------------------------------------------------------------- */
router.get('/weak-hash-users', (req, res) => {
  res.json(store.weakHashUsers.map((u) => ({ username: u.username, passwordHash: u.passwordHash, algorithm: 'MD5 (unsalted)' })));
});

router.post('/crack-hash', (req, res) => {
  const { hash } = req.body || {};
  if (!hash) return res.status(400).json({ error: 'hash is required' });
  const start = Date.now();
  // Vulnerable in spirit of the real attack: a small dictionary + fast,
  // unsalted MD5 is enough to reverse most real-world passwords instantly.
  // (Real rainbow tables do the same thing at much larger scale.)
  const match = store.COMMON_PASSWORDS.find((pw) => store.md5(pw) === hash);
  res.json({ hash, cracked: !!match, password: match || null, tookMs: Date.now() - start, dictionarySize: store.COMMON_PASSWORDS.length });
});

/* ------------------------------------------------------------------------
 * Variant 3: Reversible Encryption Instead of a One-Way Hash for
 *            Passwords — CWE-328
 *   GET /api/a02/legacy-users
 *   GET /api/a02/legacy-users/:id/decrypt
 *   These "legacy" passwords are *encrypted*, not hashed — which means
 *   they can be decrypted back to plaintext by anyone holding the key.
 *   A password should NEVER be recoverable, by design.
 * -------------------------------------------------------------------- */
router.get('/legacy-users', (req, res) => {
  res.json(store.legacyUsers.map((u) => ({ id: u.id, username: u.username, encryptedPassword: u.encryptedPassword })));
});

router.get('/legacy-users/:id/decrypt', (req, res) => {
  const user = store.legacyUsers.find((u) => u.id === Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Not found' });
  // Vulnerable: no authorization check AND the operation is even possible
  // in the first place, because the password was reversibly encrypted
  // instead of hashed. See Variant 4 for how the key itself gets exposed.
  const plaintext = store.legacyDecrypt(user.encryptedPassword);
  res.json({ username: user.username, decryptedPassword: plaintext });
});

/* ------------------------------------------------------------------------
 * Variant 4: Hard-Coded Cryptographic Keys & Secrets — CWE-321/CWE-798
 *   GET /api/a02/leaked-config
 *   Simulates what an accidentally-exposed debug/config endpoint (or a
 *   secret committed straight into source control) would reveal: the
 *   exact key + IV used to "encrypt" every record in Variant 3. Once
 *   this leaks, EVERY reversibly-encrypted record in the system is
 *   compromised at once — not just one row.
 * -------------------------------------------------------------------- */
router.get('/leaked-config', (req, res) => {
  res.json({
    warning: 'This endpoint simulates a leaked debug/config route or a hard-coded secret found in source control.',
    AES_KEY_HEX: store.HARD_CODED_KEY.toString('hex'),
    AES_IV_HEX: store.HARD_CODED_IV.toString('hex'),
    note: 'This single key/IV pair decrypts every "legacy" password in Variant 3, and reveals the identical-ciphertext pattern in Variant 5.',
  });
});

/* ------------------------------------------------------------------------
 * Variant 5: Insecure Cryptographic Mode (ECB) / Broken Algorithm
 *            — CWE-327/CWE-326
 *   POST /api/a02/ecb-demo { pin1, pin2 }
 *   ECB encrypts each block independently, so identical plaintext blocks
 *   always produce identical ciphertext — patterns leak straight through.
 *   Contrasted here with CBC + a fresh random IV, where identical
 *   plaintexts never produce identical ciphertext.
 * -------------------------------------------------------------------- */
router.post('/ecb-demo', (req, res) => {
  const { pin1 = '1234', pin2 = '1234' } = req.body || {};
  const ecb1 = store.ecbEncrypt(pin1);
  const ecb2 = store.ecbEncrypt(pin2);
  const cbc1 = store.cbcEncryptRandomIV(pin1);
  const cbc2 = store.cbcEncryptRandomIV(pin2);
  res.json({
    ecb: { pin1: ecb1, pin2: ecb2, identicalCiphertext: ecb1 === ecb2 },
    cbcWithRandomIV: { pin1: cbc1, pin2: cbc2, identicalCiphertext: cbc1.ciphertext === cbc2.ciphertext },
  });
});

/* ------------------------------------------------------------------------
 * Variant 6: Missing Encryption in Transit / Insecure Cookie Attributes
 *            — CWE-319/CWE-523
 *   GET /api/a02/security-headers
 *   The whole app runs on plain HTTP with no HSTS, and this endpoint sets
 *   a "remember me" cookie with none of the attributes that matter for
 *   transport security.
 * -------------------------------------------------------------------- */
router.get('/security-headers', (req, res) => {
  // Vulnerable: no Secure (cookie would still be sent over HTTP), no
  // HttpOnly (readable by JS/XSS), no SameSite.
  res.cookie('remember_me', 'token-in-cleartext-demo', {});
  const headers = res.getHeaders();
  res.json({
    protocol: req.protocol,
    warning: req.protocol === 'https' ? undefined : 'This request was served over plain HTTP — credentials and session cookies travel in cleartext on the network.',
    hasStrictTransportSecurity: Boolean(headers['strict-transport-security']),
    setCookieHeader: headers['set-cookie'] || null,
    missingCookieAttributes: ['Secure', 'HttpOnly', 'SameSite'],
  });
});

/* ------------------------------------------------------------------------
 * Variant 7: Insecure Randomness for a Security-Sensitive Token
 *            (Brute-Forceable Password-Reset Code) — CWE-330/CWE-338
 *   POST /api/a02/reset/request { email }
 *   POST /api/a02/reset/verify  { email, token }
 *   The reset code is generated with Math.random() (not a CSPRNG), is
 *   only 3 digits (1,000 possibilities), never expires, and the verify
 *   endpoint has no rate limiting or lockout — brute-forceable in well
 *   under a second.
 * -------------------------------------------------------------------- */
router.post('/reset/request', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });
  const token = store.generateWeakResetToken();
  store.resetTokens.set(email, { token, used: false });
  // Also demonstrates Variant 9/10: this "debug" log line leaks the
  // secret token into the logs — a second, independent way to get it.
  store.log(`Password reset requested for ${email} — token=${token} (debug logging left enabled)`);
  res.json({ message: 'If that email exists, a reset code has been sent.' });
});

router.post('/reset/verify', (req, res) => {
  const { email, token } = req.body || {};
  const entry = store.resetTokens.get(email);
  // Vulnerable: no rate limiting, no lockout, no attempt counter, no
  // expiry — an attacker can try all 1,000 possible codes in seconds.
  const valid = !!entry && !entry.used && entry.token === token;
  if (valid) entry.used = true;
  res.json({ valid });
});

/* ------------------------------------------------------------------------
 * Variant 8: Improper Certificate / TLS Validation on Outbound
 *            Requests — CWE-295
 *   GET /api/a02/tls-check?target=expired|self-signed|wrong-host|untrusted-root
 *   Compares a properly-validating HTTPS client against one configured
 *   with rejectUnauthorized:false. Uses badssl.com's public test
 *   endpoints, which are purpose-built to have exactly these certificate
 *   problems. Requires outbound internet access from wherever this
 *   server is actually running.
 * -------------------------------------------------------------------- */
const BADSSL_TARGETS = {
  expired: 'https://expired.badssl.com/',
  'self-signed': 'https://self-signed.badssl.com/',
  'wrong-host': 'https://wrong.host.badssl.com/',
  'untrusted-root': 'https://untrusted-root.badssl.com/',
};

function probe(url, rejectUnauthorized) {
  return new Promise((resolve) => {
    const req = https.get(url, { agent: new https.Agent({ rejectUnauthorized }), timeout: 6000 }, (res) => {
      resolve({ ok: true, statusCode: res.statusCode });
      res.resume();
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
  });
}

router.get('/tls-check', async (req, res) => {
  const target = req.query.target || 'expired';
  const url = BADSSL_TARGETS[target];
  if (!url) return res.status(400).json({ error: `target must be one of: ${Object.keys(BADSSL_TARGETS).join(', ')}` });

  const [secureClient, insecureClientVulnerable] = await Promise.all([
    probe(url, true), // a correctly-configured client — should reject/error
    probe(url, false), // VULNERABLE: rejectUnauthorized:false accepts the bad cert anyway
  ]);
  res.json({ target, url, secureClient, insecureClientVulnerable });
});

/* ------------------------------------------------------------------------
 * Variant 9: Sensitive Data Exposure via Logging — CWE-532
 *   POST /api/a02/legacy-login { username, password }
 *   GET  /api/a02/logs
 *   A "helpful" debug log line records the raw username AND password on
 *   every login attempt, in plaintext, to a log that this endpoint then
 *   exposes with no access control at all.
 * -------------------------------------------------------------------- */
router.post('/legacy-login', (req, res) => {
  const { username, password } = req.body || {};
  // VULN: CWE-532 — logs full credentials verbatim.
  store.log(`Login attempt username=${username} password=${password}`);
  res.status(401).json({ error: 'Invalid credentials (this demo endpoint never actually logs you in)' });
});

router.get('/logs', (req, res) => {
  // Vulnerable: no auth on an endpoint that exposes application logs,
  // which — thanks to Variants 7, 9 and 10 — contain plaintext passwords,
  // reset tokens, and session tokens.
  res.json({ lines: store.logLines });
});

/* ------------------------------------------------------------------------
 * Variant 10: Sensitive Data Exposed in a URL (Query String) — CWE-598
 *   POST /api/a02/magic-link { email }
 *   Generates a "magic login" link that carries the raw session token as
 *   a URL query parameter. URLs like this get written to server/proxy
 *   access logs, browser history, and leak via the Referer header if the
 *   page links out anywhere — all in plaintext.
 * -------------------------------------------------------------------- */
router.post('/magic-link', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });
  const token = crypto.randomBytes(16).toString('hex'); // strong token — the flaw here is WHERE it's placed, not how it's generated
  const magicLink = `/api/a02/magic-login?token=${token}&email=${encodeURIComponent(email)}`;
  // VULN: a real reverse proxy / web server access log records the full
  // request line, including the query string — token and all.
  store.log(`GET ${magicLink} 200 — (simulated access log entry)`);
  res.json({ magicLink, note: 'This link (with the token in cleartext) is what got written to the access log — check GET /api/a02/logs.' });
});

module.exports = router;
