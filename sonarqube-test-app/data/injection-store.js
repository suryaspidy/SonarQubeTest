/**
 * In-memory data + helpers for the A05: Injection screen.
 * See routes/a05.js for the exploitable endpoints and CWE mappings, sourced
 * from https://owasp.org/Top10/2025/A05_2025-Injection/
 *
 * Uses Node's built-in `node:sqlite` (no npm install required) so the SQL
 * injection variants run against a REAL SQL engine rather than a simulation.
 * Requires Node.js 22.5+. If it's unavailable, sqlAvailable is false and
 * routes/a05.js reports a clear error instead of crashing the whole app.
 */

let DatabaseSync = null;
let sqlAvailable = true;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (e) {
  sqlAvailable = false;
}

let db = null;
if (sqlAvailable) {
  db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE api_keys (id INTEGER PRIMARY KEY, service TEXT, key_value TEXT);
  `);
  db.exec(`
    INSERT INTO users (username, password, role) VALUES
      ('alice', 'alice123', 'user'),
      ('admin', 'S3cr3tAdminPW!', 'admin');
    INSERT INTO api_keys (service, key_value) VALUES
      ('stripe', 'sk_live_FAKE_demo_only_51H'),
      ('aws', 'AKIAFAKEEXAMPLE00002');
  `);
}

/* ---------------------------------------------------------------------- *
 * Variant 6: Stored XSS — in-memory comment board.
 * ---------------------------------------------------------------------- */
const comments = [];

/* ---------------------------------------------------------------------- *
 * Variant 7: NoSQL Injection — "document" store queried with a naive
 * MongoDB-style matcher that doesn't type-check operator objects.
 * ---------------------------------------------------------------------- */
const noSqlUsers = [
  { username: 'alice', password: 'alice123', role: 'user' },
  { username: 'admin', password: 'S3cr3tAdminPW!', role: 'admin' },
];

function noSqlFind(collection, query) {
  return collection.filter((doc) =>
    Object.entries(query).every(([k, v]) => {
      if (v && typeof v === 'object') {
        // VULNERABLE: a client that sends an object instead of a string
        // (e.g. {"password":{"$ne":null}}) gets its operator honored with
        // no type validation — the classic MongoDB operator-injection bug.
        if ('$ne' in v) return doc[k] !== v.$ne;
        if ('$gt' in v) return doc[k] > v.$gt;
        if ('$regex' in v) return new RegExp(v.$regex).test(doc[k]);
        return false;
      }
      return doc[k] === v;
    })
  );
}

/* ---------------------------------------------------------------------- *
 * Variant 8: LDAP Injection — naive prefix-notation filter parser/
 * evaluator, e.g. (&(uid=alice)(objectClass=person)). Real LDAP servers
 * parse filters exactly this way; unescaped input lets an attacker inject
 * extra parenthesized terms to change the filter's logical structure.
 * ---------------------------------------------------------------------- */
const ldapDirectory = [
  { uid: 'alice', cn: 'Alice A', mail: 'alice@example.com', department: 'Engineering' },
  { uid: 'admin', cn: 'Administrator', mail: 'admin@example.com', department: 'IT' },
];

function parseLdapFilter(str) {
  let i = 0;
  function parseNode() {
    if (str[i] !== '(') throw new Error(`expected "(" at position ${i}`);
    i++;
    let node;
    if (str[i] === '&' || str[i] === '|' || str[i] === '!') {
      const op = str[i];
      i++;
      const children = [];
      while (str[i] === '(') children.push(parseNode());
      node = { op, children };
    } else {
      const start = i;
      while (i < str.length && str[i] !== ')') i++;
      if (i >= str.length) throw new Error('unterminated filter');
      const leaf = str.slice(start, i);
      const eqIdx = leaf.indexOf('=');
      node = { op: 'leaf', attr: leaf.slice(0, eqIdx), value: leaf.slice(eqIdx + 1) };
    }
    if (str[i] !== ')') throw new Error(`expected ")" at position ${i}`);
    i++;
    return node;
  }
  const result = parseNode();
  return result;
}

function evalLdap(node, entry) {
  if (node.op === '&') return node.children.every((c) => evalLdap(c, entry));
  if (node.op === '|') return node.children.some((c) => evalLdap(c, entry));
  if (node.op === '!') return !evalLdap(node.children[0], entry);
  const val = entry[node.attr];
  if (node.value === '*') return val !== undefined;
  if (node.value.includes('*')) {
    const pattern = '^' + node.value.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
    return new RegExp(pattern).test(val);
  }
  return val === node.value;
}

function ldapSearch(uidInput) {
  // VULNERABLE: the caller's raw input is spliced directly into the
  // filter string — no escaping of ( ) * \ NUL as LDAP requires.
  const filterStr = `(&(uid=${uidInput})(objectClass=person))`;
  const tree = parseLdapFilter(filterStr);
  const results = ldapDirectory.filter((e) => evalLdap(tree, { ...e, objectClass: 'person' }));
  return { filterStr, results };
}

/* ---------------------------------------------------------------------- *
 * Variant 9: XPath Injection — naive boolean-expression evaluator for
 * strings like "username='alice' and password='alice123'", mirroring how
 * a real (also-vulnerable) XPath query built by string concatenation
 * would be interpreted against an XML user store.
 * ---------------------------------------------------------------------- */
const xmlUsers = [
  { username: 'alice', password: 'alice123', role: 'user' },
  { username: 'admin', password: 'S3cr3tAdminPW!', role: 'admin' },
];

function resolveOperand(row, token) {
  token = token.trim();
  const quoted = token.match(/^'(.*)'$/);
  if (quoted) return quoted[1]; // string literal
  return row[token] !== undefined ? String(row[token]) : undefined; // field reference
}

function evalNaiveBooleanExpr(row, expr) {
  const orParts = expr.split(/\s+or\s+/i);
  return orParts.some((orPart) => {
    const andParts = orPart.split(/\s+and\s+/i);
    return andParts.every((term) => {
      const eqIdx = term.indexOf('=');
      if (eqIdx === -1) return false;
      const left = resolveOperand(row, term.slice(0, eqIdx));
      const right = resolveOperand(row, term.slice(eqIdx + 1));
      return left !== undefined && left === right;
    });
  });
}

function xpathLogin(username, password) {
  // VULNERABLE: query built by string concatenation — exactly like the
  // vulnerable Java/SQL example in OWASP's own Scenario #1, applied to an
  // XPath-style lookup instead of SQL.
  const expr = `username='${username}' and password='${password}'`;
  const match = xmlUsers.find((u) => evalNaiveBooleanExpr(u, expr));
  return { expr, match };
}

/* ---------------------------------------------------------------------- *
 * Variant 10: Server-Side Template Injection (SSTI) / Expression
 * Language Injection — a minimal {{ expr }} template renderer built on
 * `new Function`, mirroring how real (also-vulnerable) template engines
 * evaluate embedded expressions. `require` is deliberately included in
 * the render context, mirroring a real, well-documented SSTI escalation
 * path in Node template engines that expose too much of their scope.
 * ---------------------------------------------------------------------- */
function naiveTemplateRender(template, context) {
  return template.replace(/\{\{(.*?)\}\}/g, (_, expr) => {
    try {
      // eslint-disable-next-line no-new-func
      return new Function('ctx', `with(ctx){ return (${expr}); }`)(context);
    } catch (e) {
      return `[template error: ${e.message}]`;
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Variant 11: Log / CRLF Injection (Log Forging) — CWE-93/CWE-117.
 * Node's http module blocks raw CRLF in actual HTTP headers (a platform-
 * level mitigation for classic header-splitting) — see routes/a05.js for
 * why this variant demonstrates the same unneutralized-newline flaw
 * against an application log instead, which is not protected the same way.
 * ---------------------------------------------------------------------- */
const auditLog = [];
function logAudit(line) {
  auditLog.push(line);
  if (auditLog.length > 200) auditLog.shift();
}

module.exports = {
  sqlAvailable,
  db,
  comments,
  noSqlUsers,
  noSqlFind,
  ldapDirectory,
  ldapSearch,
  xmlUsers,
  xpathLogin,
  naiveTemplateRender,
  auditLog,
  logAudit,
};
