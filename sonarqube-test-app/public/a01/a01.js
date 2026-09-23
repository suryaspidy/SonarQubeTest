/**
 * Front-end for the A01: Broken Access Control screen.
 * NOTE: this file itself demonstrates Variant 8 (client-side-only access
 * control) — the "force delete" button is shown/hidden based on a
 * client-side-decoded token, which is exactly the anti-pattern being taught.
 */

const CREDS = {
  alice: 'alice123',
  bob: 'bobpass',
  admin: 'Admin@123',
  carol: 'carolpass',
  mallory: 'mallorypass',
};

let currentToken = null;

function decodeTokenClientSide(token) {
  try {
    return JSON.parse(atob(token));
  } catch (e) {
    return null;
  }
}

function authHeaders() {
  return currentToken ? { Authorization: `Bearer ${currentToken}` } : {};
}

async function api(method, url, body) {
  const opts = {
    method,
    credentials: 'include', // send the a01_session cookie too (CSRF/CORS demos)
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
  };
  if (body !== undefined) opts.body = typeof body === 'string' ? body : JSON.stringify(body);
  const res = await fetch(url, opts);
  let data;
  try { data = await res.json(); } catch (e) { data = await res.text(); }
  return { status: res.status, data };
}

function show(id, result) {
  document.getElementById(id).textContent = `HTTP ${result.status}\n` + JSON.stringify(result.data, null, 2);
}

function refreshSessionUI() {
  const badge = document.getElementById('whoBadge');
  const tokenOut = document.getElementById('tokenOut');
  const forceBtn = document.getElementById('v8_btn');
  if (!currentToken) {
    badge.textContent = 'not logged in';
    badge.className = 'badge';
    tokenOut.textContent = '—';
    forceBtn.style.display = 'none';
    return;
  }
  const decoded = decodeTokenClientSide(currentToken);
  badge.textContent = `${decoded.username} (${decoded.role}, tenant ${decoded.tenantId})`;
  badge.className = 'badge' + (decoded.role === 'admin' ? ' admin' : '');
  tokenOut.textContent = currentToken;
  // VULN (Variant 8 demo): purely cosmetic client-side role check.
  forceBtn.style.display = decoded.role === 'admin' ? 'inline-block' : 'none';
}

document.getElementById('btnLogin').addEventListener('click', async () => {
  const username = document.getElementById('loginUser').value;
  const password = CREDS[username];
  const { data } = await api('POST', '/api/a01/login', { username, password });
  if (data && data.token) {
    currentToken = data.token;
    refreshSessionUI();
  }
});

document.getElementById('btnLogout').addEventListener('click', async () => {
  await api('POST', '/api/a01/logout');
  currentToken = null;
  refreshSessionUI();
});

/* Variant 1 — IDOR */
async function v1() {
  const id = document.getElementById('v1_id').value;
  show('v1_out', await api('GET', `/api/a01/orders/${id}`));
}

/* Variant 2 — Vertical privilege escalation */
async function v2() {
  show('v2_out', await api('GET', '/api/a01/admin/users'));
}

/* Variant 3 — Mass assignment */
async function v3() {
  const id = document.getElementById('v3_id').value;
  const bodyRaw = document.getElementById('v3_body').value;
  let body;
  try { body = JSON.parse(bodyRaw); } catch (e) { return show('v3_out', { status: 'client-error', data: 'Invalid JSON' }); }
  show('v3_out', await api('PUT', `/api/a01/users/${id}/profile`, body));
}

/* Variant 4 — HTTP verb tampering */
async function v4get() {
  const id = document.getElementById('v4_id').value;
  show('v4_out', await api('GET', `/api/a01/admin/orders/${id}`));
}
async function v4del() {
  const id = document.getElementById('v4_id').value;
  show('v4_out', await api('DELETE', `/api/a01/admin/orders/${id}`));
}

/* Variant 5 — Tenant isolation bypass */
async function v5() {
  const id = document.getElementById('v5_id').value;
  show('v5_out', await api('GET', `/api/a01/tenants/${id}/orders`));
}

/* Variant 6 — JWT tampering */
function v6encode() {
  const raw = document.getElementById('v6_json').value;
  try {
    const obj = JSON.parse(raw);
    currentToken = btoa(JSON.stringify(obj));
    refreshSessionUI();
    show('v6_out', { status: 'client', data: { message: 'Token replaced with your edited claims — now call whoami or any other endpoint above.' } });
  } catch (e) {
    show('v6_out', { status: 'client-error', data: 'Invalid JSON' });
  }
}
async function v6() {
  show('v6_out', await api('GET', '/api/a01/whoami'));
}

/* Variant 7 — handled by window.open in HTML */

/* Variant 8 — client-side-only access control */
async function v8() {
  const id = document.getElementById('v8_id').value;
  show('v8_out', await api('DELETE', `/api/a01/orders/${id}/force`));
}

/* Variant 9 — CORS misconfiguration */
async function v9() {
  show('v9_out', await api('GET', '/api/a01/account'));
}

/* Variant 10 — CSRF (manual test button; see csrf-poc.html for the real PoC) */
async function v10() {
  const to = document.getElementById('v10_to').value;
  const amount = document.getElementById('v10_amt').value;
  show('v10_out', await api('GET', `/api/a01/transfer?to=${encodeURIComponent(to)}&amount=${encodeURIComponent(amount)}`));
}

/* Variant 11 — Path traversal */
async function v11() {
  const tenant = document.getElementById('v11_tenant').value;
  const name = document.getElementById('v11_name').value;
  show('v11_out', await api('GET', `/api/a01/files?tenant=${encodeURIComponent(tenant)}&name=${encodeURIComponent(name)}`));
}

refreshSessionUI();

/* "Learn A01" deep-dive modal */
const learnModal = document.getElementById('learnModal');
document.getElementById('btnLearn').addEventListener('click', () => {
  learnModal.classList.add('open');
});
document.getElementById('btnCloseLearn').addEventListener('click', () => {
  learnModal.classList.remove('open');
});
learnModal.addEventListener('click', (e) => {
  if (e.target === learnModal) learnModal.classList.remove('open'); // click outside the panel closes it
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') learnModal.classList.remove('open');
});
