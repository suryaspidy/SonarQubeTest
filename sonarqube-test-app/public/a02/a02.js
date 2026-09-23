/**
 * Front-end for the A02: Security Misconfiguration screen. No login is
 * required — every variant is about how the app/server/platform is
 * configured, not who's asking.
 */

async function api(method, url, body, headers) {
  const opts = { method, headers: { 'Content-Type': 'application/json', ...(headers || {}) } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  let data;
  try { data = await res.json(); } catch (e) { data = await res.text(); }
  return { status: res.status, data };
}

function show(id, result) {
  document.getElementById(id).textContent = `HTTP ${result.status}\n` + JSON.stringify(result.data, null, 2);
}

/* Variant 1 — Default admin credentials */
async function v1() {
  const username = document.getElementById('v1_user').value;
  const password = document.getElementById('v1_pass').value;
  show('v1_out', await api('POST', '/api/a02/admin-login', { username, password }));
}

/* Variant 2 — Directory listing + exposed files */
async function v2() {
  show('v2_out', await api('GET', '/api/a02/directory-listing'));
}

/* Variant 3 — Verbose error / stack trace */
async function v3() {
  show('v3_out', await api('GET', '/api/a02/trigger-error'));
}

/* Variant 4 — Active debug code (eval endpoint) */
async function v4() {
  const expr = document.getElementById('v4_expr').value;
  show('v4_out', await api('GET', `/api/a02/debug/eval?expr=${encodeURIComponent(expr)}`));
}

/* Variant 5 — Env var exposure */
async function v5() {
  show('v5_out', await api('GET', '/api/a02/debug/env'));
}

/* Variant 6 — Hard-coded bypass constant */
async function v6(withBypass) {
  const headers = withBypass ? { 'X-Internal-Bypass': 'lab-internal-9f3a' } : {};
  show('v6_out', await api('GET', '/api/a02/premium-report', undefined, headers));
}

/* Variant 7 — Insecure cookie flags */
async function v7() {
  show('v7_out', await api('GET', '/api/a02/admin-session'));
}

/* Variant 8 — Permissive cloud storage */
async function v8list() {
  show('v8_list_out', await api('GET', '/api/a02/cloud-bucket'));
}
async function v8get() {
  const key = document.getElementById('v8_key').value;
  show('v8_out', await api('GET', `/api/a02/cloud-bucket/${key}`));
}

/* Variant 9 — XXE */
async function v9() {
  const xml = document.getElementById('v9_xml').value;
  show('v9_out', await api('POST', '/api/a02/xxe-parse', { xml }));
}

/* "Learn A02" deep-dive modal */
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
