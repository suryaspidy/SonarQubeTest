/**
 * ============================================================================
 *  ⚠️  OWASP A02:2025 — SECURITY MISCONFIGURATION  ⚠️
 * ============================================================================
 * Every route below is deliberately vulnerable, for training / SonarQube
 * SAST validation / manual DAST practice only. No login is required —
 * security misconfiguration is about how the app/server/platform is set
 * up, not who's asking. Reference:
 * https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
 * ============================================================================
 */

const express = require('express');
const store = require('../data/misconfig-store');

const router = express.Router();

/* ------------------------------------------------------------------------
 * Variant 1: Default / Unchanged Admin Credentials — CWE-16
 *            (OWASP Example Attack Scenario #1)
 *   POST /api/a02/admin-login { username, password }
 *   The admin console was installed with a well-known default
 *   username/password, and nobody ever rotated it.
 * -------------------------------------------------------------------- */
router.post('/admin-login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === store.adminAccount.username && password === store.adminAccount.password) {
    return res.json({
      success: true,
      message: `Logged in as admin using the FACTORY DEFAULT credentials (${store.adminAccount.username}/${store.adminAccount.password}), which ${store.adminAccount.rotated ? 'have' : 'have NOT'} been rotated since install.`,
    });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

/* ------------------------------------------------------------------------
 * Variant 2: Directory Listing Enabled + Exposed Backup/Config Files
 *            — CWE-16 (commonly cited as CWE-548 / CWE-530)
 *            (OWASP Example Attack Scenario #2)
 *   GET /api/a02/directory-listing
 *   GET /legacy-uploads/<filename>   (real static files — see server.js)
 *   A "legacy uploads" folder was mounted with directory listing and
 *   dotfiles both left enabled, exposing a stale .env backup, a database
 *   dump, and internal notes to anyone who requests the folder.
 * -------------------------------------------------------------------- */
router.get('/directory-listing', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const dir = path.join(__dirname, '..', 'misconfigured-uploads');
  fs.readdir(dir, (err, files) => {
    if (err) return res.status(500).json({ error: err.message });
    // Vulnerable: lists every file in the folder — including dotfiles and
    // backups that were never meant to be web-accessible — with a direct,
    // real download link for each (served by the static mount in server.js).
    res.json({
      folder: '/legacy-uploads/',
      files: files.map((name) => ({ name, url: `/legacy-uploads/${name}` })),
      note: 'Each of these is a real, downloadable file — try GET /legacy-uploads/.env.backup',
    });
  });
});

/* ------------------------------------------------------------------------
 * Variant 3: Verbose Error Messages / Stack Trace Disclosure — CWE-16
 *            (commonly cited as CWE-209 / CWE-215)
 *            (OWASP Example Attack Scenario #3)
 *   GET /api/a02/trigger-error
 *   No central error-handling middleware sanitizes failures on this
 *   route — the raw exception, full stack trace, file paths, and runtime
 *   version are all sent straight to the client.
 * -------------------------------------------------------------------- */
router.get('/trigger-error', (req, res) => {
  try {
    // Deliberately throws — simulates an unexpected runtime error.
    null.triggerTypeError();
  } catch (err) {
    // Vulnerable: no generic "Something went wrong" response — the
    // internals of the server are handed straight to the caller.
    res.status(500).json({
      error: err.message,
      stack: err.stack,
      nodeVersion: process.version,
      cwd: process.cwd(),
      note: 'A hardened error handler would log this internally and return only a generic message + correlation ID.',
    });
  }
});

/* ------------------------------------------------------------------------
 * Variant 4: Active Debug Code Left Enabled in Production — CWE-489 / CWE-11
 *   GET /api/a02/debug/eval?expr=2+2
 *   A developer convenience endpoint for evaluating expressions during
 *   local debugging was gated behind a DEBUG_MODE flag that was supposed
 *   to default to false in production — but the "TODO: flip this off
 *   before deploy" was never done.
 * -------------------------------------------------------------------- */
const DEBUG_MODE = true; // TODO: set to false before deploying to production — never done (see misconfigured-uploads/internal-notes.txt)

if (DEBUG_MODE) {
  router.get('/debug/eval', (req, res) => {
    const expr = req.query.expr || '1+1';
    try {
      // VULNERABLE: arbitrary expression evaluation, left reachable
      // because DEBUG_MODE was never disabled for this deployment.
      // eslint-disable-next-line no-eval
      const result = eval(expr);
      res.json({ expr, result, warning: 'DEBUG_MODE is true in this "production" instance — this endpoint should not exist here at all.' });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });
}

/* ------------------------------------------------------------------------
 * Variant 5: Sensitive Information Exposure via Environment
 *            Variables — CWE-526
 *   GET /api/a02/debug/env
 *   A diagnostics endpoint meant for local troubleshooting dumps the
 *   full environment — including database credentials and cloud/API
 *   secrets — with no authentication.
 * -------------------------------------------------------------------- */
router.get('/debug/env', (req, res) => {
  // Vulnerable: no auth, and no redaction of anything secret-shaped.
  res.json({ env: store.simulatedProdEnv, note: 'A real /debug/env endpoint like this has caused real breaches — this one uses fake demo values.' });
});

/* ------------------------------------------------------------------------
 * Variant 6: Use of a Hard-Coded, Security-Relevant Constant — CWE-547
 *   GET /api/a02/premium-report  (header: X-Internal-Bypass)
 *   A "premium" feature is gated by a hard-coded bypass token meant only
 *   for internal QA use — but it's a static string baked into the
 *   source (and, as it happens, also sitting in the exposed
 *   internal-notes.txt from Variant 2).
 * -------------------------------------------------------------------- */
router.get('/premium-report', (req, res) => {
  const bypass = req.header('X-Internal-Bypass');
  if (bypass === store.INTERNAL_BYPASS_TOKEN) {
    return res.json({ report: 'FULL PREMIUM REPORT CONTENT — Q4 revenue, customer list, forecasts...', bypassedViaHardcodedConstant: true });
  }
  res.status(402).json({ error: 'Payment required', hint: 'A hard-coded internal bypass constant also unlocks this — see if you can find it (try Variant 2\'s exposed files).' });
});

/* ------------------------------------------------------------------------
 * Variant 7: Sensitive Cookie Missing Secure / HttpOnly / SameSite
 *            — CWE-614 / CWE-1004
 *   GET /api/a02/admin-session
 *   An admin session cookie is issued with none of the attributes that
 *   protect it in transit or from script access.
 * -------------------------------------------------------------------- */
router.get('/admin-session', (req, res) => {
  // Vulnerable: no Secure (sent over plain HTTP too), no HttpOnly
  // (readable by any injected script), no SameSite (sent cross-site).
  res.cookie('admin_session', 'admin-session-demo-token', {});
  res.json({
    message: 'admin_session cookie set with NO Secure/HttpOnly/SameSite attributes.',
    missingAttributes: ['Secure', 'HttpOnly', 'SameSite'],
  });
});

/* ------------------------------------------------------------------------
 * Variant 8: Overly Permissive Default Cloud Storage Permissions — CWE-16
 *            (OWASP Example Attack Scenario #4)
 *   GET /api/a02/cloud-bucket
 *   GET /api/a02/cloud-bucket/:key
 *   A mock object-storage bucket where every object defaulted to
 *   "public-read" on upload and nobody tightened the policy — anyone can
 *   list or fetch any object with zero credentials.
 * -------------------------------------------------------------------- */
router.get('/cloud-bucket', (req, res) => {
  res.json({ bucket: 'company-exports-prod', objects: store.cloudBucket.map((o) => ({ key: o.key, acl: o.acl })) });
});

router.get('/cloud-bucket/*', (req, res) => {
  const key = req.params[0];
  const obj = store.cloudBucket.find((o) => o.key === key);
  if (!obj) return res.status(404).json({ error: 'No such object' });
  // Vulnerable: no bucket-policy / IAM check at all — "public-read" was
  // left as the default ACL for every object.
  res.json({ key: obj.key, acl: obj.acl, content: obj.content });
});

/* ------------------------------------------------------------------------
 * Variant 9: XML External Entity (XXE) Injection via Misconfigured
 *            Parser — CWE-611 / CWE-776
 *   POST /api/a02/xxe-parse { xml }
 *   The XML parser resolves DOCTYPE external entities by default — a
 *   configuration flaw, not a coding bug in the traditional sense. See
 *   data/misconfig-store.js for why this is simulated rather than using
 *   a real (also-vulnerable) native XML library.
 * -------------------------------------------------------------------- */
router.post('/xxe-parse', (req, res) => {
  const { xml } = req.body || {};
  if (!xml) return res.status(400).json({ error: 'xml is required' });
  const { resolved, entitiesResolved } = store.vulnerableXmlEntityResolve(xml);
  res.json({ resolved, entitiesResolved, note: entitiesResolved.length ? 'External entity was resolved and its file contents inlined into the document.' : 'No external entities found in the supplied XML.' });
});

module.exports = router;
