/**
 * Front-end for the A04: Cryptographic Failures screen. No login is
 * required for this category — every variant is about data at rest, in
 * transit, or crypto primitives, not about who's asking.
 */

async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  let data;
  try { data = await res.json(); } catch (e) { data = await res.text(); }
  return { status: res.status, data };
}

function show(id, result) {
  document.getElementById(id).textContent = `HTTP ${result.status}\n` + JSON.stringify(result.data, null, 2);
}

/* Variant 1 — Cleartext storage at rest */
async function v1() {
  show('v1_out', await api('GET', '/api/a04/payment-methods'));
}

/* Variant 2 — Weak/broken hashing */
async function v2list() {
  show('v2_list_out', await api('GET', '/api/a04/weak-hash-users'));
}
async function v2crack() {
  const hash = document.getElementById('v2_hash').value.trim();
  if (!hash) return show('v2_out', { status: 'client-error', data: 'Paste a passwordHash first (fetch the list above).' });
  show('v2_out', await api('POST', '/api/a04/crack-hash', { hash }));
}

/* Variant 3 — Reversible encryption instead of hashing */
async function v3list() {
  show('v3_list_out', await api('GET', '/api/a04/legacy-users'));
}
async function v3decrypt() {
  const id = document.getElementById('v3_id').value;
  show('v3_out', await api('GET', `/api/a04/legacy-users/${id}/decrypt`));
}

/* Variant 4 — Hard-coded keys */
async function v4() {
  show('v4_out', await api('GET', '/api/a04/leaked-config'));
}

/* Variant 5 — ECB vs CBC+random IV */
async function v5() {
  const pin1 = document.getElementById('v5_pin1').value;
  const pin2 = document.getElementById('v5_pin2').value;
  show('v5_out', await api('POST', '/api/a04/ecb-demo', { pin1, pin2 }));
}

/* Variant 6 — Transport & cookie security */
async function v6() {
  show('v6_out', await api('GET', '/api/a04/security-headers'));
}

/* Variant 7 — Insecure randomness / brute-forceable reset token */
async function v7request() {
  const email = document.getElementById('v7_email').value;
  show('v7_req_out', await api('POST', '/api/a04/reset/request', { email }));
}

async function v7bruteforce() {
  const email = document.getElementById('v7_email').value;
  const out = document.getElementById('v7_out');
  out.textContent = 'Brute-forcing 000-999…';
  const start = Date.now();
  const BATCH = 50;
  for (let base = 0; base < 1000; base += BATCH) {
    const batch = [];
    for (let i = base; i < Math.min(base + BATCH, 1000); i++) {
      const token = String(i).padStart(3, '0');
      batch.push(
        api('POST', '/api/a04/reset/verify', { email, token }).then((r) => ({ token, ...r.data }))
      );
    }
    const results = await Promise.all(batch);
    const found = results.find((r) => r.valid);
    if (found) {
      out.textContent = `Cracked in ${Date.now() - start}ms — valid reset code was "${found.token}" (tried up to ${base + BATCH} of 1000 combinations).`;
      return;
    }
  }
  out.textContent = `No valid code found in ${Date.now() - start}ms — did you click "Request reset code" first?`;
}

/* Variant 8 — TLS certificate validation */
async function v8() {
  const target = document.getElementById('v8_target').value;
  show('v8_out', await api('GET', `/api/a04/tls-check?target=${encodeURIComponent(target)}`));
}

/* Variant 9 — Sensitive data in logs */
async function v9login() {
  const username = document.getElementById('v9_user').value;
  const password = document.getElementById('v9_pass').value;
  show('v9_out', await api('POST', '/api/a04/legacy-login', { username, password }));
}

/* Shared log viewer (Variants 9 & 10) */
async function viewLogs(outId) {
  show(outId, await api('GET', '/api/a04/logs'));
}

/* Variant 10 — Sensitive data in URL */
async function v10() {
  const email = document.getElementById('v10_email').value;
  show('v10_out', await api('POST', '/api/a04/magic-link', { email }));
}

/* "Learn A04" deep-dive modal */
const learnModal = document.getElementById('learnModal');
document.getElementById('btnLearn').addEventListener('click', () => {
  learnModal.classList.add('open');
});
document.getElementById('btnCloseLearn').addEventListener('click', () => {
  learnModal.classList.remove('open');
});
learnModal.addEventListener('click', (e) => {
  if (e.target === learnModal) learnModal.classList.remove('open');
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') learnModal.classList.remove('open');
});
