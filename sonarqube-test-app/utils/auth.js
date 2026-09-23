/**
 * ============================================================================
 *  ⚠️  INTENTIONALLY VULNERABLE — SHARED "AUTH" LAYER  ⚠️
 * ============================================================================
 * Used by the A01: Broken Access Control screen (and reused by later
 * categories, e.g. A07: Identification & Authentication Failures).
 *
 * VULN (root cause for several A01 variants): CWE-347 Improper
 * Verification of Cryptographic Signature.
 *
 * issueToken() just base64-encodes a JSON payload. There is NO signature
 * (no HMAC, no JWT `alg`/signature verification, nothing). Anyone who has
 * a token can:
 *   1. base64-decode it
 *   2. edit any field (role, tenantId, id, username)
 *   3. base64 re-encode it
 *   4. send it back as `Authorization: Bearer <token>`
 * ...and the server will trust it completely. This single flaw is what
 * makes the "JWT / Token Tampering" variant possible, and it's *also* what
 * an attacker would use to actually carry out several of the other
 * variants (IDOR, vertical escalation, tenant bypass) against a target
 * that has no other authentication of its own.
 *
 * DO NOT copy this pattern into real code. A real implementation must use
 * a signed/verified token (e.g. a proper JWT library with signature
 * verification and algorithm allow-listing, or server-side sessions).
 * ============================================================================
 */

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
// embedded in the client-supplied token, with no signature check and no
// re-verification against the database on every request.
function fakeAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  // Also accept the token from the insecure session cookie set at login,
  // so the CSRF demo (cookie-only auth) and the Bearer-token demo (API
  // clients) both work against the same routes.
  const cookieToken = req.cookies && req.cookies.a01_session;
  const token = bearer || cookieToken || null;
  req.user = token ? decodeToken(token) : null;
  next();
}

// Correct-looking helper that several routes below simply forget to call
// — that omission is itself the vulnerability being demonstrated
// (missing function-level access control / HTTP verb tampering).
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin role required' });
  }
  next();
}

module.exports = { issueToken, decodeToken, fakeAuth, requireAdmin };
