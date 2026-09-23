# OWASP Top 10:2025 Learning Lab

⚠️ **Intentionally vulnerable application.** Built for local security training,
SonarQube (SAST) rule validation, and manual/DAST practice (OWASP ZAP, Burp
Suite, curl). Never deploy this to a shared network or the public internet.

This project follows the **[OWASP Top 10:2025](https://owasp.org/Top10/2025/)**
ordering and naming — not the older, more widely-known 2021 list. The two
lists differ substantially past #1:

| # | 2025 | (for reference) 2021 |
|---|------|------|
| A01 | Broken Access Control | Broken Access Control |
| A02 | **Security Misconfiguration** | Cryptographic Failures |
| A03 | Software Supply Chain Failures | Injection |
| A04 | **Cryptographic Failures** | Insecure Design |
| A05 | Injection | Security Misconfiguration |
| A06 | Insecure Design | Vulnerable & Outdated Components |
| A07 | Authentication Failures | Identification & Authentication Failures |
| A08 | Software or Data Integrity Failures | Software & Data Integrity Failures |
| A09 | Security Logging and Alerting Failures | Security Logging & Monitoring Failures |
| A10 | Mishandling of Exceptional Conditions | Server-Side Request Forgery (SSRF) |

## Structure

The app has one screen per OWASP Top 10:2025 category, reachable from the
dashboard at `/`. **A01 (Broken Access Control)**, **A02 (Security
Misconfiguration)**, **A04 (Cryptographic Failures)**, and **A05
(Injection)** are implemented so far — the rest (A03, A06–A10) are
placeholder screens, ready to be filled in the same way, category by
category.

```
server.js                  Express app entry point, mounts each category's router
utils/auth.js               Shared (deliberately unsigned) token issue/verify + middleware (A01)
data/store.js                In-memory users/orders "database" + two demo tenants (A01)
data/misconfig-store.js      In-memory data + helpers for default creds, env dump, XXE, etc. (A02)
data/crypto-store.js         In-memory data + weak crypto helpers (A04)
data/injection-store.js      node:sqlite database + LDAP/XPath/NoSQL/template helpers (A05)
routes/a01.js               All A01 vulnerable endpoints, under /api/a01/*
routes/a02.js               All A02 vulnerable endpoints, under /api/a02/*
routes/a04.js               All A04 vulnerable endpoints, under /api/a04/*
routes/a05.js               All A05 vulnerable endpoints, under /api/a05/*
private/                   Per-tenant files used by the A01 path-traversal variant
misconfigured-uploads/      Exposed .env/backup/notes files used by the A02 directory-listing variant
public/index.html          Dashboard — links to each category screen
public/a01/                 A01 screen: index.html (UI), a01.js (client logic),
                            admin-panel.html (forced-browsing target),
                            csrf-poc.html (simulated malicious page)
public/a02/                 A02 screen: index.html (UI), a02.js (client logic)
public/a04/                 A04 screen: index.html (UI), a04.js (client logic)
public/a05/                 A05 screen: index.html (UI), a05.js (client logic)
public/a03, a06 … a10       Placeholder screens
```

**Requires Node.js 22.5+** — the A05 screen's SQL injection variants use
Node's built-in `node:sqlite` module (no npm install needed for it, but it
does need a recent enough Node runtime). Everything else works on any
Node version Express 4 supports.

## Running it

```bash
npm install
npm start
# open http://localhost:3000
```

## Demo accounts (A01)

| username | password     | role  | tenant     |
|----------|--------------|-------|------------|
| alice    | alice123     | user  | Acme Corp  |
| bob      | bobpass      | user  | Globex Inc |
| admin    | Admin@123    | admin | Acme Corp  |
| carol    | carolpass    | user  | Globex Inc |
| mallory  | mallorypass  | user  | Acme Corp (attacker persona used by the CSRF PoC) |

A02, A04, and A05 need no login — those categories are about how the
app/platform is configured, how data is protected, and how input is
handled, not about who's asking.

## A01:2025 — Broken Access Control

The auth layer (`utils/auth.js`) issues a token that is just
`base64(JSON.stringify(payload))` — **no signature at all**. That single root
cause (CWE-347) is what makes several variants below trivially exploitable:
decode the token, edit `role`/`tenantId`/`id`, re-encode, resend.

| # | Variant | CWE | Endpoint |
|---|---------|-----|----------|
| 1 | Insecure Direct Object Reference (IDOR) / Horizontal Privilege Escalation | CWE-639 | `GET /api/a01/orders/:id` |
| 2 | Vertical Privilege Escalation (Missing Function-Level Access Control) | CWE-862 | `GET /api/a01/admin/users` |
| 3 | Mass Assignment / Parameter Tampering (Privilege Escalation via Payload) | CWE-915 | `PUT /api/a01/users/:id/profile` |
| 4 | HTTP Verb / Method Tampering | CWE-650 | `GET`/`DELETE /api/a01/admin/orders/:id` |
| 5 | Multi-Tenant Data Leakage (Tenant Isolation Bypass) | CWE-668 | `GET /api/a01/tenants/:tenantId/orders` |
| 6 | JWT / Token Tampering (Trusting an Unsigned Claim) | CWE-347 | `GET /api/a01/whoami` |
| 7 | Forced Browsing to an Unprotected Admin Resource | CWE-425 | `GET /a01/admin-panel.html` + `GET /api/a01/admin/stats` |
| 8 | Client-Side-Only Access Control | CWE-602 | `DELETE /api/a01/orders/:id/force` |
| 9 | CORS Misconfiguration (Overly Permissive Cross-Origin Access) | CWE-942 | `GET /api/a01/account` |
| 10 | Cross-Site Request Forgery (CSRF) | CWE-352 | `GET /api/a01/transfer` |
| 11 | Path Traversal Bypassing Access Restriction on Files | CWE-22 / CWE-23 | `GET /api/a01/files` |

Variants 1–5 were the ones requested up front; 6–11 were added because
they're also officially part of OWASP's A01:2025 category — confirmed
against [owasp.org/Top10/2025/A01](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/),
whose own mapped-CWE list includes CWE-639, CWE-862, CWE-425, CWE-668,
CWE-352, and CWE-22/23. (CWE-942 CORS misconfiguration is, as of the 2025
list, officially filed under **A02** — see below — but is kept live here on
the A01 screen for continuity.)

Each variant's panel on the `/a01/` screen includes: what to try, a live
"Try it" control wired to the real API, and a remediation note. Full exploit
narratives and the vulnerable code itself are commented inline in
`routes/a01.js` and `utils/auth.js`.

### Quick manual walkthrough

1. Open `http://localhost:3000/a01/` and log in as **alice**.
2. Variant 1: fetch order `2` (bob's) — returned with no ownership check.
3. Variant 2: call the admin users list while still alice — works.
4. Variant 6: edit the decoded token to `"role":"admin"`, re-encode, then
   retry variant 2/4/anything admin-gated — now it "legitimately" passes the
   (broken) admin check too.
5. Variant 10: log in as alice, then open the CSRF PoC page in a new tab —
   watch alice's credits move to mallory with no confirmation.

## A02:2025 — Security Misconfiguration

No login is required for this screen. Content is sourced directly from
[owasp.org/Top10/2025/A02](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/):
this category jumped from #5 (2021) to **#2** (2025), the biggest riser on
the list, with **100%** of tested apps showing some form of misconfiguration
and 719,084 total occurrences across 16 mapped CWEs.

| # | Variant | CWE | Endpoint |
|---|---------|-----|----------|
| 1 | Default / Unchanged Admin Credentials | CWE-16 | `POST /api/a02/admin-login` |
| 2 | Directory Listing Enabled + Exposed Backup/Config Files | CWE-16 / CWE-548 / CWE-530 | `GET /api/a02/directory-listing`, `GET /legacy-uploads/*` |
| 3 | Verbose Error Messages / Stack Trace Disclosure | CWE-16 / CWE-209 / CWE-215 | `GET /api/a02/trigger-error` |
| 4 | Active Debug Code Left Enabled in Production | CWE-489 / CWE-11 | `GET /api/a02/debug/eval` |
| 5 | Sensitive Information Exposure via Environment Variables | CWE-526 | `GET /api/a02/debug/env` |
| 6 | Use of a Hard-Coded, Security-Relevant Constant | CWE-547 | `GET /api/a02/premium-report` |
| 7 | Sensitive Cookie Missing Secure / HttpOnly / SameSite | CWE-614 / CWE-1004 | `GET /api/a02/admin-session` |
| 8 | Overly Permissive Default Cloud Storage Permissions | CWE-16 | `GET /api/a02/cloud-bucket` |
| 9 | XML External Entity (XXE) Injection via Misconfigured Parser | CWE-611 / CWE-776 | `POST /api/a02/xxe-parse` |

Variants 1, 2, 3, and 8 mirror OWASP's own four Example Attack Scenarios for
this category almost verbatim; Variant 9 (XXE) and the CWE-16 (Configuration)
citation are the two CWEs OWASP's background note calls out by name.

Note: the XXE demo (Variant 9) uses a small hand-rolled entity resolver
(`data/misconfig-store.js`) rather than a real native XML library, since
Node has no built-in DTD-aware XML parser to misconfigure — it's documented
inline as a faithful simulation of how a real vulnerable parser (e.g.
libxml2, or Java's `DocumentBuilderFactory` with insecure defaults) behaves.

### Quick manual walkthrough

1. Open `http://localhost:3000/a02/` (no login needed).
2. Variant 2: list `/legacy-uploads/`, then open `.env.backup` — real
   database and cloud credentials, served as a plain static file.
3. Variant 6: call the premium report without the bypass header (402), then
   with `X-Internal-Bypass: lab-internal-9f3a` (the same value leaked in
   Variant 2's `internal-notes.txt`) — full content, no payment.
4. Variant 9: submit the default XXE payload — it reads this app's own
   `private/secrets.txt` and inlines it into the response.

## A04:2025 — Cryptographic Failures

No login is required for this screen either — cryptographic failures are
about how data is stored, transmitted, and transformed, not who's allowed to
ask for it. The shared (also intentionally weak) crypto helpers live in
`data/crypto-store.js`, including one hard-coded AES key/IV used across
several variants — leaking that single key (Variant 4) compromises
everything encrypted with it (Variant 3, Variant 5).

| # | Variant | CWE | Endpoint |
|---|---------|-----|----------|
| 1 | Cleartext Storage of Sensitive Data at Rest | CWE-312 / CWE-313 | `GET /api/a04/payment-methods` |
| 2 | Weak / Broken Hashing Algorithm for Passwords (unsalted MD5) | CWE-327 / CWE-759 | `GET /api/a04/weak-hash-users`, `POST /api/a04/crack-hash` |
| 3 | Reversible Encryption Instead of a One-Way Hash for Passwords | CWE-328 | `GET /api/a04/legacy-users/:id/decrypt` |
| 4 | Hard-Coded Cryptographic Keys & Secrets | CWE-321 / CWE-798 | `GET /api/a04/leaked-config` |
| 5 | Insecure Cryptographic Mode (ECB) / Broken Algorithm | CWE-327 / CWE-326 | `POST /api/a04/ecb-demo` |
| 6 | Missing Encryption in Transit / Insecure Cookie Attributes | CWE-319 / CWE-523 | `GET /api/a04/security-headers` |
| 7 | Insecure Randomness for a Security Token (brute-forceable reset code) | CWE-330 / CWE-338 | `POST /api/a04/reset/request`, `POST /api/a04/reset/verify` |
| 8 | Improper Certificate / TLS Validation on Outbound Requests | CWE-295 | `GET /api/a04/tls-check` |
| 9 | Sensitive Data Exposure via Logging | CWE-532 | `POST /api/a04/legacy-login`, `GET /api/a04/logs` |
| 10 | Sensitive Data Exposed in a URL (Query String) | CWE-598 | `POST /api/a04/magic-link` |

Note: Variant 8 (TLS certificate validation) calls out to public
[badssl.com](https://badssl.com) test endpoints and needs real outbound
internet access from wherever the server runs.

### Quick manual walkthrough

1. Open `http://localhost:3000/a04/` (no login needed).
2. Variant 2: fetch the weak-hash user list, copy bob's hash, crack it —
   instantly recovers "letmein".
3. Variant 4: reveal the leaked key/IV, then Variant 3: decrypt dave's
   "legacy" password using that same key — full plaintext recovery.
4. Variant 5: leave both PINs as "1234" — ECB ciphertexts match; change one
   and CBC-with-random-IV never matches even when they're the same.
5. Variant 7: click "Request reset code", then "Brute-force all 1,000
   possible codes" — cracked in under a second.
6. Variant 9: trigger a login attempt, then view server logs — your
   password is sitting there in plaintext.

## A05:2025 — Injection

No login is required for this screen. Content is sourced directly from
[owasp.org/Top10/2025/A05](https://owasp.org/Top10/2025/A05_2025-Injection/):
this category sits at #5 (down from #3 in 2021), but has the most mapped
CWEs (37) and the most total CVEs (62,445) of any 2025 category. The SQL
injection variants run against a **real embedded SQLite database** via
Node's built-in `node:sqlite` module — not a simulation.

| # | Variant | CWE | Endpoint |
|---|---------|-----|----------|
| 1 | SQL Injection: Authentication Bypass | CWE-89 | `POST /api/a05/sql-login` |
| 2 | SQL Injection: UNION-Based Data Exfiltration | CWE-89 | `GET /api/a05/search` |
| 3 | OS Command Injection | CWE-77 / CWE-78 | `GET /api/a05/ping` |
| 4 | Code Injection via eval() | CWE-94 / CWE-95 | `POST /api/a05/calculate` |
| 5 | Reflected Cross-Site Scripting (XSS) | CWE-79 | `GET /api/a05/greet` |
| 6 | Stored Cross-Site Scripting (XSS) | CWE-79 / CWE-80 | `POST`/`GET /api/a05/comments` |
| 7 | NoSQL Injection (Operator Injection) | CWE-943 | `POST /api/a05/nosql-login` |
| 8 | LDAP Injection | CWE-90 | `GET /api/a05/ldap-search` |
| 9 | XPath Injection | CWE-91 / CWE-643 | `POST /api/a05/xpath-login` |
| 10 | Server-Side Template Injection (SSTI) / EL Injection | CWE-917 / CWE-94 | `POST /api/a05/welcome` |
| 11 | Log / CRLF Injection (Log Forging) | CWE-93 / CWE-117 | `POST /api/a05/log-event`, `GET /api/a05/logs` |

Variants 1, 3 mirror OWASP's own Example Attack Scenarios almost verbatim.
Variants 5–6 (XSS) and Variants 1–2 (SQLi) are the two named-by-name,
highest-CVE-count injection types in OWASP's background note. Variants 7–9
(NoSQL/LDAP/XPath) cover every other interpreter OWASP's description text
names by name ("SQL, NoSQL, OS command, ORM, LDAP, and EL/OGNL injection").

Notes on two variants that needed adaptation for a real Node.js app:
- **Variant 8 (LDAP)** and **Variant 9 (XPath)** use small hand-rolled
  parser/evaluators (`data/injection-store.js`) rather than a real LDAP
  server or XML database, since Node has neither built in — documented
  inline as faithful simulations of how real (also-vulnerable) parsers
  behave, same approach used for the A02 XXE demo.
- **Variant 11 (Log/CRLF injection)**: Node's `http` module blocks raw CRLF
  in actual HTTP header values (`ERR_INVALID_CHAR`) — a platform-level fix
  for classic HTTP response splitting — so this variant demonstrates the
  same unneutralized-newline flaw against an application log instead, which
  has no equivalent protection.

### Quick manual walkthrough

1. Open `http://localhost:3000/a05/` (no login needed).
2. Variant 1: submit `' OR '1'='1' --` as the username — authenticates as
   the first user in a real SQLite table with no valid password.
3. Variant 2: search `' UNION SELECT service, key_value FROM api_keys --` —
   leaks fake Stripe/AWS keys disguised as user rows.
4. Variant 5: click "Open in new tab" — the injected `<script>` actually
   runs, proving reflected XSS (fetch alone would only show inert text).
5. Variant 10: try `{{ 7*7 }}` first (renders "49"), then the full RCE
   payload — returns the real output of `whoami` from the server.

## Extending to the next category

When you're ready for the next OWASP category (A03: Software Supply Chain
Failures and A06: Insecure Design are the two still open before A07, which
is already partially covered by A01's JWT-tampering variant, …):

1. Add `routes/aXX.js` following the same pattern (import a dedicated
   `data/*-store.js` as needed).
2. Mount it in `server.js`: `app.use('/api/aXX', aXXRoutes)`.
3. Build `public/aXX/index.html` + `public/aXX/aXX.js` replacing the
   placeholder, following the A01/A02/A04/A05 screens' layout (one
   `<section class="variant">` per variant, remediation footer, and a
   "Learn AXX" deep-dive modal sourced from `owasp.org/Top10/2025/AXX_...`).
4. Flip that category's `ready: false` to `ready: true` in
   `public/index.html`.
