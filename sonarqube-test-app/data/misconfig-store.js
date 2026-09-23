/**
 * In-memory data + helpers for the A02: Security Misconfiguration screen.
 * See routes/a02.js for the exploitable endpoints and CWE mappings, sourced
 * from https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
 */

/* ---------------------------------------------------------------------- *
 * VULN (Variant 1): factory-default admin console credentials that were
 * never rotated after install — OWASP's own Example Attack Scenario #1.
 * ---------------------------------------------------------------------- */
const adminAccount = { username: 'admin', password: 'admin', rotated: false };

/* ---------------------------------------------------------------------- *
 * VULN (Variant 5): CWE-526 — a "diagnostics" snapshot of what production
 * environment variables would contain. Deliberately fake values — this is
 * NOT the sandbox's real process.env — but shaped exactly like a real one,
 * to show what a debug/actuator endpoint like this would actually leak.
 * ---------------------------------------------------------------------- */
const simulatedProdEnv = {
  NODE_ENV: 'production',
  DB_HOST: 'prod-db.internal',
  DB_USER: 'app_service',
  DB_PASSWORD: 'Pr0d_D8_P@ssw0rd_2026!',
  JWT_SIGNING_SECRET: 'b3a3f9c2-fake-signing-secret-do-not-use',
  AWS_ACCESS_KEY_ID: 'AKIAFAKEEXAMPLE00001',
  AWS_SECRET_ACCESS_KEY: 'wJalrFAKE/EXAMPLE/SecretKeyForDemoOnly',
  STRIPE_SECRET_KEY: 'sk_live_FAKE_demo_only_51H',
};

/* ---------------------------------------------------------------------- *
 * VULN (Variant 6): CWE-547 — Use of a Hard-Coded, Security-Relevant
 * Constant. A "premium report" feature gate can be bypassed by anyone who
 * knows (or finds — see the exposed internal-notes.txt in Variant 2) this
 * single hard-coded string.
 * ---------------------------------------------------------------------- */
const INTERNAL_BYPASS_TOKEN = 'lab-internal-9f3a';

/* ---------------------------------------------------------------------- *
 * VULN (Variant 8): CWE-16 / Example Attack Scenario #4 — a mock
 * object-storage bucket where every object defaulted to "public-read" on
 * creation, and nobody ever tightened it. No credential is required to
 * list or fetch any object.
 * ---------------------------------------------------------------------- */
const cloudBucket = [
  { key: 'customer-exports/2026-01-report.csv', acl: 'public-read', content: 'id,name,email\n1,Jane Doe,jane.doe@example.com\n2,John Smith,john.smith@example.com' },
  { key: 'backups/db-snapshot-2026-02.sql.gz', acl: 'public-read', content: '[binary SQL dump — fake demo placeholder]' },
  { key: 'internal/quarterly-financials.xlsx', acl: 'public-read', content: '[fake spreadsheet bytes — demo placeholder]' },
];

/* ---------------------------------------------------------------------- *
 * VULN (Variant 9): CWE-611/CWE-776 — a hand-rolled, deliberately naive
 * XML "parser" that resolves DOCTYPE external entities by plain text
 * substitution, mirroring the exact behavior of real vulnerable parsers
 * (e.g. libxml2, or Java's DocumentBuilderFactory before external entity
 * resolution is disabled) when DTD/XXE protections are left at their
 * insecure historical defaults. Node's built-in tooling has no XML parser
 * and does NOT do this natively — this function exists purely to give the
 * lab a safe, dependency-free way to demonstrate the exact failure mode.
 * ---------------------------------------------------------------------- */
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..');

function vulnerableXmlEntityResolve(xml) {
  // 1. Collect <!ENTITY name SYSTEM "file://..."> declarations.
  const entityRegex = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"file:\/\/(.*?)"\s*>/g;
  const entities = {};
  let m;
  while ((m = entityRegex.exec(xml)) !== null) {
    const [, name, filePath] = m;
    try {
      // VULNERABLE: reads whatever local file path the caller specified,
      // with no allow-list — this is the actual "External Entity" flaw.
      // (Resolved relative to the project root so the demo is portable
      // across machines; a real file:// URI would be a true absolute
      // filesystem path, and "../" segments still escape this root.)
      entities[name] = fs.readFileSync(path.join(PROJECT_ROOT, filePath), 'utf8');
    } catch (e) {
      entities[name] = `[failed to resolve external entity: ${e.message}]`;
    }
  }
  // 2. Substitute &name; references anywhere in the document.
  let resolved = xml;
  for (const [name, value] of Object.entries(entities)) {
    resolved = resolved.split(`&${name};`).join(value);
  }
  return { resolved, entitiesResolved: Object.keys(entities) };
}

module.exports = {
  adminAccount,
  simulatedProdEnv,
  INTERNAL_BYPASS_TOKEN,
  cloudBucket,
  vulnerableXmlEntityResolve,
};
