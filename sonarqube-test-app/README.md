# OWASP Top 10 (2021) Learning Lab

⚠️ **Intentionally vulnerable application.** Built for local security training,
SonarQube (SAST) rule validation, and manual/DAST practice (OWASP ZAP, Burp
Suite, curl). Never deploy this to a shared network or the public internet.

## Structure

The app has one screen per OWASP Top 10 (2021) category, reachable from the
dashboard at `/`. **A01: Broken Access Control** and **A02: Cryptographic
Failures** are implemented so far — the rest (A03–A10) are placeholder
screens, ready to be filled in the same way, category by category.

```
server.js               Express app entry point, mounts each category's router
utils/auth.js           Shared (deliberately unsigned) token issue/verify + middleware
data/store.js           In-memory users/orders "database" + two demo tenants (A01)
data/crypto-store.js    In-memory data + weak crypto helpers (A02)
routes/a01.js           All A01 vulnerable endpoints, under /api/a01/*
routes/a02.js           All A02 vulnerable endpoints, under /api/a02/*
private/                Per-tenant files used by the A01 path-traversal variant
public/index.html       Dashboard — links to each category screen
public/a01/             A01 screen: index.html (UI), a01.js (client logic),
                        admin-panel.html (forced-browsing target),
                        csrf-poc.html (simulated malicious page)
public/a02/             A02 screen: index.html (UI), a02.js (client logic)
public/a03 … public/a10 Placeholder screens
```

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

## A01:2021 — Broken Access Control

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
they're also officially part of OWASP's A01:2021 category (either directly —
CSRF and the CWE-22/23 path-traversal CWEs are explicitly mapped to A01 in
the 2021 revision — or because they're extremely common real-world causes of
broken access control that complement the first five: unsigned/tampered
tokens, forced browsing, UI-only enforcement, and permissive CORS).

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

## A02:2021 — Cryptographic Failures

No login is required for this screen — cryptographic failures are about how
data is stored, transmitted, and transformed, not who's allowed to ask for
it. The shared (also intentionally weak) crypto helpers live in
`data/crypto-store.js`, including one hard-coded AES key/IV used across
several variants — leaking that single key (Variant 4) compromises
everything encrypted with it (Variant 3, Variant 5).

| # | Variant | CWE | Endpoint |
|---|---------|-----|----------|
| 1 | Cleartext Storage of Sensitive Data at Rest | CWE-312 / CWE-313 | `GET /api/a02/payment-methods` |
| 2 | Weak / Broken Hashing Algorithm for Passwords (unsalted MD5) | CWE-327 / CWE-759 | `GET /api/a02/weak-hash-users`, `POST /api/a02/crack-hash` |
| 3 | Reversible Encryption Instead of a One-Way Hash for Passwords | CWE-328 | `GET /api/a02/legacy-users/:id/decrypt` |
| 4 | Hard-Coded Cryptographic Keys & Secrets | CWE-321 / CWE-798 | `GET /api/a02/leaked-config` |
| 5 | Insecure Cryptographic Mode (ECB) / Broken Algorithm | CWE-327 / CWE-326 | `POST /api/a02/ecb-demo` |
| 6 | Missing Encryption in Transit / Insecure Cookie Attributes | CWE-319 / CWE-523 | `GET /api/a02/security-headers` |
| 7 | Insecure Randomness for a Security Token (brute-forceable reset code) | CWE-330 / CWE-338 | `POST /api/a02/reset/request`, `POST /api/a02/reset/verify` |
| 8 | Improper Certificate / TLS Validation on Outbound Requests | CWE-295 | `GET /api/a02/tls-check` |
| 9 | Sensitive Data Exposure via Logging | CWE-532 | `POST /api/a02/legacy-login`, `GET /api/a02/logs` |
| 10 | Sensitive Data Exposed in a URL (Query String) | CWE-598 | `POST /api/a02/magic-link` |

Note: Variant 8 (TLS certificate validation) calls out to public
[badssl.com](https://badssl.com) test endpoints and needs real outbound
internet access from wherever the server runs.

### Quick manual walkthrough

1. Open `http://localhost:3000/a02/` (no login needed).
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

## Extending to the next category

When you're ready for the next OWASP category (A03, A04, …):

1. Add `routes/aXX.js` following the same pattern (import a dedicated
   `data/*-store.js` as needed).
2. Mount it in `server.js`: `app.use('/api/aXX', aXXRoutes)`.
3. Build `public/aXX/index.html` + `public/aXX/aXX.js` replacing the
   placeholder, following the A01/A02 screens' layout (one
   `<section class="variant">` per variant, remediation footer, and a
   "Learn AXX" deep-dive modal).
4. Flip that category's `ready: false` to `ready: true` in
   `public/index.html`.
