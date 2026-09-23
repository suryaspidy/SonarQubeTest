/**
 * ============================================================================
 *  ⚠️  OWASP TOP 10 (2021) LEARNING LAB — INTENTIONALLY VULNERABLE  ⚠️
 * ============================================================================
 *  Purpose : A screen per OWASP Top 10 category, each with hands-on,
 *            exploitable examples for security training, SonarQube (SAST)
 *            rule validation, and manual/DAST practice (e.g. OWASP ZAP,
 *            Burp Suite).
 *
 *  Status  : A01 (Broken Access Control) is fully implemented. A02–A10
 *            are placeholder screens, to be filled in next.
 *
 *  DO NOT deploy this application to production, a shared network, or the
 *  public internet. It contains deliberate security flaws by design.
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');

const a01Routes = require('./routes/a01');

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------------------------------------------------------------------- *
 * VULN: CWE-942 Permissive Cross-Origin Resource Sharing (SAST)
 * Reflects any Origin back and allows credentials — see A01 Variant 9
 * (routes/a01.js: GET /api/a01/account) for the exploitable consequence.
 * ---------------------------------------------------------------------- */
app.use(cors({ origin: true, credentials: true }));

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* No helmet / no security headers configured on purpose
 * -> contributes to A05: Security Misconfiguration (covered later). */

app.use(express.static(path.join(__dirname, 'public')));

/* ------------------------------ Category routers ------------------------------ */
app.use('/api/a01', a01Routes);

// Future: app.use('/api/a02', a02Routes); etc., as each category is built.

app.listen(PORT, () => {
  console.log(`OWASP Top 10 Learning Lab running at http://localhost:${PORT}`);
  console.log('WARNING: intentionally vulnerable — do not expose to an untrusted network.');
});
