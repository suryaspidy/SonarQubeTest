/**
 * ============================================================================
 *  ⚠️  OWASP TOP 10:2025 LEARNING LAB — INTENTIONALLY VULNERABLE  ⚠️
 * ============================================================================
 *  Purpose : A screen per OWASP Top 10:2025 category, each with hands-on,
 *            exploitable examples for security training, SonarQube (SAST)
 *            rule validation, and manual/DAST practice (e.g. OWASP ZAP,
 *            Burp Suite).
 *
 *            This project follows the OWASP Top 10:2025 ordering/naming
 *            (https://owasp.org/Top10/2025/), NOT the older 2021 list:
 *              A01 Broken Access Control            A06 Insecure Design
 *              A02 Security Misconfiguration         A07 Authentication Failures
 *              A03 Software Supply Chain Failures    A08 Software or Data Integrity Failures
 *              A04 Cryptographic Failures            A09 Security Logging and Alerting Failures
 *              A05 Injection                         A10 Mishandling of Exceptional Conditions
 *
 *  Status  : A01 (Broken Access Control), A02 (Security Misconfiguration),
 *            A04 (Cryptographic Failures), and A05 (Injection) are fully
 *            implemented. A03, A06–A10 are placeholder screens, to be
 *            filled in next.
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
const a02Routes = require('./routes/a02');
const a04Routes = require('./routes/a04');
const a05Routes = require('./routes/a05');

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------------------------------------------------------------------- *
 * VULN: CWE-942 Permissive Cross-Origin Resource Sharing (SAST)
 * Reflects any Origin back and allows credentials — see A01 Variant 9
 * (routes/a01.js: GET /api/a01/account) for the exploitable consequence.
 * Officially, OWASP 2025 maps CWE-942 under A02: Security Misconfiguration —
 * it's kept live under A01 here for continuity; see the A02 Learn modal.
 * ---------------------------------------------------------------------- */
app.use(cors({ origin: true, credentials: true }));

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* No helmet / no security headers configured on purpose — itself an example
 * of A02: Security Misconfiguration (missing security headers). */

app.use(express.static(path.join(__dirname, 'public')));

/* ---------------------------------------------------------------------- *
 * VULN (A02 Variant 2): CWE-16 / CWE-548 — a second static mount mimicking
 * a "legacy uploads" folder that was configured with dotfiles explicitly
 * allowed and no directory-listing hardening. See routes/a02.js and
 * misconfigured-uploads/ for the exposed backup/config files this serves.
 * ---------------------------------------------------------------------- */
app.use('/legacy-uploads', express.static(path.join(__dirname, 'misconfigured-uploads'), { dotfiles: 'allow' }));

/* ------------------------------ Category routers ------------------------------ */
app.use('/api/a01', a01Routes);
app.use('/api/a02', a02Routes);
app.use('/api/a04', a04Routes);
app.use('/api/a05', a05Routes);

// Future: app.use('/api/a03', a03Routes); etc., as each category is built.

app.listen(PORT, () => {
  console.log(`OWASP Top 10:2025 Learning Lab running at http://localhost:${PORT}`);
  console.log('WARNING: intentionally vulnerable — do not expose to an untrusted network.');
});
