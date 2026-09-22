# SonarQube Test App

An **intentionally vulnerable** Node.js/Express web application built to validate
security-testing tooling — specifically SonarQube's static analysis (SAST), and
optionally a DAST scanner (OWASP ZAP) or an IAST agent (e.g. Contrast, Seeker)
run against the live app.

> ⚠️ **This app is deliberately insecure.** Never deploy it to a shared network,
> a cloud VM with a public IP, or production. Run it only on localhost / an
> isolated container for testing.

---

## What "SAST / DAST / IAST" actually means here

| Type | What it tests | Tool in this workflow |
|------|----------------|------------------------|
| **SAST** (Static) | Reads source code without running it; flags risky patterns (SQL string concat, `eval`, hardcoded secrets, weak crypto, etc.) | **SonarQube** — this is what SonarQube is built for |
| **DAST** (Dynamic) | Sends real HTTP requests to the *running* app and observes behavior (reflected payloads, redirects, headers) | **OWASP ZAP** or **Burp Suite** (SonarQube itself does not do DAST) |
| **IAST** (Interactive) | An agent instrumented inside the running app watches code paths as you exercise it via the UI/API | A dedicated IAST agent (e.g. Contrast Community Edition) — not a SonarQube feature |

So: use SonarQube for the SAST pass on the source code, and (optionally) point
ZAP or an IAST agent at the running app for the other two. The app below gives
you real findings for all three.

---

## Vulnerabilities included

| # | Endpoint | Vulnerability | CWE |
|---|----------|---------------|-----|
| 1 | `GET /search?q=` | SQL Injection (string concatenation) | CWE-89 |
| 2 | `GET /greet?name=` | Reflected XSS | CWE-79 |
| 3 | `POST/GET /comments` | Stored XSS | CWE-79 |
| 4 | `GET /ping?host=` | OS Command Injection | CWE-78 |
| 5 | `GET /file?name=` | Path Traversal | CWE-22 |
| 6 | `POST /login` | Hardcoded credentials, weak hash (MD5), sensitive data in logs | CWE-798, CWE-327, CWE-532 |
| 7 | `GET /profile/:id` | Insecure Direct Object Reference (no auth check) | CWE-639 |
| 8 | `GET /redirect?url=` | Open Redirect | CWE-601 |
| 9 | `GET /fetch?url=` | Server-Side Request Forgery (SSRF) | CWE-918 |
| 10 | `POST /calculate` | Code Injection via `eval()` | CWE-95 |
| 11 | `GET /debug` | Information Disclosure (env vars, secrets) | CWE-215 |
| 12 | `POST /import` | Insecure Deserialization (`Function` constructor) | CWE-502 |

### OWASP A01:2021 — Broken Access Control (8 variants)

Login via `POST /login` first (e.g. `alice`/`alice123`, `bob`/`bobpass`, or
`admin`/`Admin@123`), then send the returned token as
`Authorization: Bearer <token>`. The dashboard's "Broken Access Control"
panel does all of this for you, including a button that decodes and
tampers with the token in the browser.

> The token itself is **unsigned** (`base64(JSON)`, see `issueToken`/
> `decodeToken` in `server.js`) — that lack of a signature is what makes
> Variant 6 (and by extension several others) exploitable.

| # | Endpoint | Vulnerability | CWE |
|---|----------|---------------|-----|
| 1 | `GET /api/orders/:id` | IDOR / Horizontal Privilege Escalation — read another user's order by changing the id | CWE-639 |
| 2 | `GET /api/admin/users` | Vertical Privilege Escalation — admin-only listing missing its `requireAdmin` check | CWE-862 |
| 3 | `PUT /api/users/:id/profile` | Mass Assignment — request body merged straight onto the DB row, so `{"role":"admin"}` sticks | CWE-915 |
| 4 | `GET` vs `DELETE /api/admin/orders/:id` | HTTP Verb Tampering — GET is protected, DELETE on the same path forgot the same check | CWE-650 |
| 5 | `GET /api/tenants/:tenantId/orders` | Multi-Tenant Data Leakage — tenant ID from the URL is trusted instead of the token's tenant | CWE-668 |
| 6 | `GET /api/whoami` | JWT/Token Tampering — server trusts an unsigned, client-editable role claim | CWE-347 |
| 7 | `GET /admin.html` | Forced Browsing — admin panel reachable directly, no auth check, just unlinked from the nav | CWE-425 |
| 8 | `DELETE /api/orders/:id/force` | Client-Side-Only Access Control — restriction exists only as a hidden UI button, zero backend check | CWE-602 |

Variants 1–5 are the ones most commonly tested for OWASP A01; 6–8 round out
the same category with related, equally common real-world patterns
(unsigned tokens, forced browsing, and security-through-UI-hiding).

Plus app-wide issues SonarQube will also flag:
- Overly permissive CORS (`origin: '*'` with `credentials: true`) — CWE-942
- Missing security headers (no Helmet/CSP/HSTS) — CWE-693
- Verbose error messages leaking internals — CWE-209

A dashboard UI (`public/index.html`) lets you trigger every case from a browser
— useful when driving a DAST scan or IAST agent, not just SAST.

---

## Project structure

```
sonarqube-test-app/
├── server.js                 # Express app with all vulnerable routes
├── package.json
├── sonar-project.properties   # SonarScanner CLI config
├── .gitignore
├── files/notes.txt            # target file for the path-traversal demo
└── public/
    ├── index.html             # dashboard to exercise every test case
    ├── style.css
    └── app.js
```

---

## Running it locally

```bash
npm install
npm start
# App runs at http://localhost:3000
```

Open `http://localhost:3000` in a browser to use the dashboard, or hit the
endpoints directly with curl, e.g.:

```bash
curl "http://localhost:3000/search?q=' OR '1'='1"
curl "http://localhost:3000/file?name=../../../../etc/passwd"
```

---

## Running a SonarQube SAST scan

### Option A — SonarQube Community Server via Docker (quickest)

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
# wait ~1 min, then log in at http://localhost:9000 (default admin/admin, forced reset)
```

Create a project and a token in the SonarQube UI (My Account → Security →
Generate Token), then from the project root:

```bash
# Install the scanner CLI (macOS example; see SonarQube docs for your OS)
brew install sonar-scanner

sonar-scanner \
  -Dsonar.projectKey=sonarqube-test-app \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<YOUR_GENERATED_TOKEN>
```

The `sonar-project.properties` file already in this repo sets most of this,
so once configured you can usually just run `sonar-scanner -Dsonar.token=...`.

### Option B — SonarCloud / SonarQube Cloud

If your org uses SonarQube's hosted SaaS instead, connect the Git repo
directly in the SonarQube Cloud UI ("Analyze new project" → pick your repo)
and it will scan on push via its own CI integration — no local scanner needed.

### What to expect

SonarQube's SAST engine should flag most of the 12 issues above (SQL
injection via string concatenation, `eval`/`Function` usage, weak hash
algorithms, hardcoded credentials, permissive CORS, logging of sensitive
data) as **Security Hotspots** or **Vulnerabilities**, categorized by
severity (Blocker/Critical/Major) and mapped to CWE/OWASP Top 10 categories
in the SonarQube dashboard.

---

## (Optional) Running a DAST pass with OWASP ZAP

```bash
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://host.docker.internal:3000 -r zap-report.html
```

ZAP will independently discover things like the reflected XSS, open
redirect, and missing security headers by actually sending requests to the
running app — a good complement to SonarQube's static findings.

---

## Pushing this project to your own Git repository

From inside the `sonarqube-test-app` folder:

```bash
# 1. Initialize git (skip if already a repo)
git init

# 2. Stage and commit everything
git add .
git commit -m "Add intentionally vulnerable app for SonarQube SAST/DAST testing"

# 3. Create an empty repo on GitHub/GitLab/Bitbucket first (via their web UI),
#    then link it as the remote — replace the URL with your repo's URL:
git remote add origin https://github.com/<your-username>/sonarqube-test-app.git

# 4. Rename local branch to main (if it isn't already)
git branch -M main

# 5. Push
git push -u origin main
```

If you're using SSH instead of HTTPS:

```bash
git remote add origin git@github.com:<your-username>/sonarqube-test-app.git
git push -u origin main
```

If the remote repo already has commits (e.g. a README created on GitHub),
pull first to avoid a rejected push:

```bash
git pull origin main --allow-unrelated-histories
git push -u origin main
```

### Suggested `.gitignore` note
`node_modules/` is already excluded — anyone cloning the repo just runs
`npm install` to restore dependencies.

---

## Safe-guarding this repo

Since this code is intentionally vulnerable, consider:
- Naming the repo clearly (e.g. `sonarqube-test-app`, or add a `SECURITY.md`
  stating it's a test fixture) so it isn't mistaken for production code.
- Keeping it in a private repo unless it's meant to be a public teaching example.
- Not connecting the running instance to any real, sensitive data source —
  the seeded SQLite database is in-memory and resets on every restart.
