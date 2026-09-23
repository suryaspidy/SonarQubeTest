/**
 * In-memory "database" + crypto helpers for the A02: Cryptographic Failures
 * screen. Everything here is deliberately weak — see routes/a02.js for the
 * exploitable endpoints and the exact CWE each piece maps to.
 */

const crypto = require('crypto');

/* ---------------------------------------------------------------------- *
 * VULN (Variant 4): CWE-321 / CWE-798 — Use of a Hard-Coded Cryptographic
 * Key. This key + IV are baked into the source, checked into version
 * control, and (in this lab) even exposed via a debug endpoint. Whoever
 * has them can decrypt every "reversibly encrypted" record below.
 * ---------------------------------------------------------------------- */
const HARD_CODED_KEY = crypto.createHash('sha256').update('lab-super-secret-key-2021').digest(); // 32 bytes for AES-256
const HARD_CODED_IV = Buffer.from('0123456789abcdef'); // 16 bytes, static/reused for every record — also wrong on its own (CWE-329)

/* ---------------------------------------------------------------------- *
 * VULN (Variant 1): CWE-312 — Cleartext Storage of Sensitive Information.
 * Full card number + CVV stored as plain strings, exactly as a real
 * database dump or backup would contain them. A PCI-DSS violation.
 * ---------------------------------------------------------------------- */
const paymentMethods = [
  { id: 1, user: 'alice', cardNumber: '4111111111111111', cvv: '123', expiry: '04/27' },
  { id: 2, user: 'bob', cardNumber: '5500000000000004', cvv: '456', expiry: '11/26' },
  { id: 3, user: 'carol', cardNumber: '340000000000009', cvv: '789', expiry: '07/28' },
];

/* ---------------------------------------------------------------------- *
 * VULN (Variant 2): CWE-327 / CWE-759 — Use of a Broken Hash (MD5) With No
 * Salt for password storage. MD5 is fast and has no per-user salt, so
 * common passwords are recoverable instantly via a small lookup table
 * (a "rainbow table" in miniature).
 * ---------------------------------------------------------------------- */
function md5(input) {
  return crypto.createHash('md5').update(input).digest('hex');
}

const weakHashUsers = [
  { id: 1, username: 'alice', passwordHash: md5('alice123') },
  { id: 2, username: 'bob', passwordHash: md5('letmein') },
  { id: 3, username: 'carol', passwordHash: md5('password1') },
];

// A tiny slice of a real-world common-password list — enough to prove the
// point. Real rainbow tables / cracking dictionaries contain billions of
// precomputed hashes for exactly this kind of unsalted MD5/SHA1 password.
const COMMON_PASSWORDS = [
  'password', 'password1', '123456', '123456789', 'qwerty', 'letmein',
  'admin', 'welcome', 'monkey', 'dragon', 'alice123', 'iloveyou', 'abc123',
];

/* ---------------------------------------------------------------------- *
 * VULN (Variant 3): CWE-328 — Use of a Reversible Encryption Algorithm
 * Instead of a One-Way Hash for passwords. Because it's *encrypted*
 * rather than *hashed*, anyone with HARD_CODED_KEY (i.e. anyone who can
 * read the source, or hits the leaked-config endpoint from Variant 4)
 * can recover the original plaintext password — hashing is designed to
 * make that mathematically infeasible; reversible encryption is not.
 * ---------------------------------------------------------------------- */
function legacyEncrypt(plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', HARD_CODED_KEY, HARD_CODED_IV);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('hex');
}

function legacyDecrypt(hex) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', HARD_CODED_KEY, HARD_CODED_IV);
  return Buffer.concat([decipher.update(Buffer.from(hex, 'hex')), decipher.final()]).toString('utf8');
}

const legacyUsers = [
  { id: 1, username: 'dave', encryptedPassword: legacyEncrypt('SuperSecret!42') },
  { id: 2, username: 'erin', encryptedPassword: legacyEncrypt('Tr0ub4dor&3') },
];

/* ---------------------------------------------------------------------- *
 * VULN (Variant 5): CWE-327 / CWE-326 — Insecure Cryptographic Mode (ECB).
 * ECB encrypts each fixed-size block independently, so identical
 * plaintext blocks always produce identical ciphertext blocks — patterns
 * in the plaintext (e.g. two users choosing the same PIN) leak straight
 * through the "encryption".
 * ---------------------------------------------------------------------- */
function ecbEncrypt(plaintext) {
  const cipher = crypto.createCipheriv('aes-256-ecb', HARD_CODED_KEY, null);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('hex');
}

// Secure contrast: AES-256-CBC with a fresh random IV per call — identical
// plaintexts never produce identical ciphertext.
function cbcEncryptRandomIV(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', HARD_CODED_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), ciphertext: ciphertext.toString('hex') };
}

/* ---------------------------------------------------------------------- *
 * VULN (Variant 7): CWE-330 / CWE-338 — Use of Insufficiently Random /
 * Cryptographically Weak Values for a security-sensitive token.
 * Math.random() is a fast, statistically-biased, NON-cryptographic PRNG
 * — it must never be used for tokens, password resets, session IDs, or
 * API keys. Combined here with a tiny 3-digit keyspace and NO rate
 * limiting on the verify endpoint, the token is brute-forceable in well
 * under a second from a browser tab.
 * ---------------------------------------------------------------------- */
const resetTokens = new Map(); // email -> { token, used }

function generateWeakResetToken() {
  // VULNERABLE: Math.random() (not crypto.randomInt) AND only 3 digits
  // (1000 possible values) — should be crypto.randomInt(0, 1e6) or better,
  // a long random string, with expiry + rate limiting + lockout.
  return String(Math.floor(Math.random() * 1000)).padStart(3, '0');
}

/* ---------------------------------------------------------------------- *
 * Shared in-memory "log" used by Variants 9 & 10 to make CWE-532
 * (sensitive data in logs) and CWE-598 (sensitive data in URLs, which
 * then end up in these same logs) visible without needing to tail a
 * real log file.
 * ---------------------------------------------------------------------- */
const logLines = [];
function log(line) {
  logLines.push(`[${new Date().toISOString()}] ${line}`);
  if (logLines.length > 200) logLines.shift();
}

module.exports = {
  HARD_CODED_KEY,
  HARD_CODED_IV,
  paymentMethods,
  weakHashUsers,
  COMMON_PASSWORDS,
  md5,
  legacyUsers,
  legacyEncrypt,
  legacyDecrypt,
  ecbEncrypt,
  cbcEncryptRandomIV,
  resetTokens,
  generateWeakResetToken,
  logLines,
  log,
};
