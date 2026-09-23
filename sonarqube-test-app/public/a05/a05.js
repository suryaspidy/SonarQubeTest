/**
 * Front-end for the A05: Injection screen. No login is required.
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

/* Variant 1 — SQLi auth bypass */
async function v1() {
  const username = document.getElementById('v1_user').value;
  const password = document.getElementById('v1_pass').value;
  show('v1_out', await api('POST', '/api/a05/sql-login', { username, password }));
}

/* Variant 2 — SQLi UNION exfiltration */
async function v2() {
  const q = document.getElementById('v2_q').value;
  show('v2_out', await api('GET', `/api/a05/search?q=${encodeURIComponent(q)}`));
}

/* Variant 3 — OS command injection */
async function v3() {
  const host = document.getElementById('v3_host').value;
  show('v3_out', await api('GET', `/api/a05/ping?host=${encodeURIComponent(host)}`));
}

/* Variant 4 — Code injection via eval() */
async function v4() {
  const expression = document.getElementById('v4_expr').value;
  show('v4_out', await api('POST', '/api/a05/calculate', { expression }));
}

/* Variant 5 — Reflected XSS */
function v5open() {
  const name = document.getElementById('v5_name').value;
  window.open(`/api/a05/greet?name=${encodeURIComponent(name)}`, '_blank');
}
async function v5fetch() {
  const name = document.getElementById('v5_name').value;
  const res = await fetch(`/api/a05/greet?name=${encodeURIComponent(name)}`);
  const text = await res.text();
  document.getElementById('v5_out').textContent = `HTTP ${res.status}\n${text}`;
}

/* Variant 6 — Stored XSS */
async function v6post() {
  const body = document.getElementById('v6_comment').value;
  show('v6_out', await api('POST', '/api/a05/comments', { body }));
}
function v6open() {
  window.open('/api/a05/comments', '_blank');
}

/* Variant 7 — NoSQL injection */
async function v7() {
  const raw = document.getElementById('v7_json').value;
  let body;
  try { body = JSON.parse(raw); } catch (e) { return show('v7_out', { status: 'client-error', data: 'Invalid JSON' }); }
  show('v7_out', await api('POST', '/api/a05/nosql-login', body));
}

/* Variant 8 — LDAP injection */
async function v8() {
  const uid = document.getElementById('v8_uid').value;
  show('v8_out', await api('GET', `/api/a05/ldap-search?uid=${encodeURIComponent(uid)}`));
}

/* Variant 9 — XPath injection */
async function v9() {
  const username = document.getElementById('v9_user').value;
  const password = document.getElementById('v9_pass').value;
  show('v9_out', await api('POST', '/api/a05/xpath-login', { username, password }));
}

/* Variant 10 — SSTI / EL injection */
async function v10() {
  const name = document.getElementById('v10_name').value;
  show('v10_out', await api('POST', '/api/a05/welcome', { name }));
}

/* Variant 11 — Log/CRLF injection */
async function v11post() {
  const username = document.getElementById('v11_user').value;
  show('v11_out', await api('POST', '/api/a05/log-event', { username }));
}
async function v11view() {
  show('v11_out', await api('GET', '/api/a05/logs'));
}

/* "Learn A05" deep-dive modal */
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
