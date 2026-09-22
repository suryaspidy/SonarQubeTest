async function runSearch() {
  const q = document.getElementById('sqlInput').value;
  const res = await fetch(`/search?q=${encodeURIComponent(q)}`);
  document.getElementById('sqlOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function runGreet() {
  const name = document.getElementById('xssInput').value;
  const res = await fetch(`/greet?name=${encodeURIComponent(name)}`);
  // Intentionally injected via innerHTML to demonstrate reflected XSS end-to-end
  document.getElementById('xssOut').innerHTML = await res.text();
}

async function postComment() {
  const body = document.getElementById('commentInput').value;
  await fetch('/comments', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
  });
  loadComments();
}

async function loadComments() {
  const res = await fetch('/comments');
  document.getElementById('commentsOut').innerHTML = await res.text();
}

async function runPing() {
  const host = document.getElementById('pingInput').value;
  const res = await fetch(`/ping?host=${encodeURIComponent(host)}`);
  document.getElementById('pingOut').textContent = await res.text();
}

async function runFile() {
  const name = document.getElementById('fileInput').value;
  const res = await fetch(`/file?name=${encodeURIComponent(name)}`);
  document.getElementById('fileOut').textContent = await res.text();
}

async function runLogin() {
  const username = document.getElementById('userInput').value;
  const password = document.getElementById('passInput').value;
  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  document.getElementById('loginOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function runIdor() {
  const id = document.getElementById('idorInput').value;
  const res = await fetch(`/profile/${id}`);
  document.getElementById('idorOut').textContent = JSON.stringify(await res.json(), null, 2);
}

function runRedirect() {
  const url = document.getElementById('redirectInput').value;
  window.location.href = `/redirect?url=${encodeURIComponent(url)}`;
}

async function runFetch() {
  const url = document.getElementById('ssrfInput').value;
  const res = await fetch(`/fetch?url=${encodeURIComponent(url)}`);
  document.getElementById('ssrfOut').textContent = await res.text();
}

async function runCalc() {
  const expression = document.getElementById('evalInput').value;
  const res = await fetch('/calculate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ expression }),
  });
  document.getElementById('calcOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function runDebug() {
  const res = await fetch('/debug');
  document.getElementById('debugOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function runImport() {
  const data = document.getElementById('importInput').value;
  const res = await fetch('/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data }),
  });
  document.getElementById('importOut').textContent = JSON.stringify(await res.json(), null, 2);
}

/* ---------------------------------------------------------------- *
 * OWASP A01:2021 — Broken Access Control panel
 * localStorage is fine here: this is a real standalone app the user
 * runs on their own machine, not a Claude.ai in-browser artifact.
 * ------------------------------------------------------------------ */
function acToken() {
  return localStorage.getItem('ac_token') || '';
}
function acAuthHeaders() {
  return { Authorization: `Bearer ${acToken()}`, 'Content-Type': 'application/json' };
}

async function acLogin() {
  const username = document.getElementById('acUser').value;
  const password = document.getElementById('acPass').value;
  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (data.token) localStorage.setItem('ac_token', data.token);
  document.getElementById('acLoginOut').textContent = JSON.stringify(data, null, 2);
  document.getElementById('acTokenOut').textContent = acToken();
}

async function acIdorOrder() {
  const id = document.getElementById('idorOrderId').value;
  const res = await fetch(`/api/orders/${id}`, { headers: acAuthHeaders() });
  document.getElementById('acIdorOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function acAdminUsers() {
  const res = await fetch('/api/admin/users', { headers: acAuthHeaders() });
  document.getElementById('acAdminUsersOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function acMassAssign() {
  const id = document.getElementById('acMassId').value;
  const body = document.getElementById('acMassBody').value;
  const res = await fetch(`/api/users/${id}/profile`, {
    method: 'PUT',
    headers: acAuthHeaders(),
    body,
  });
  document.getElementById('acMassOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function acVerbGet() {
  const id = document.getElementById('acVerbId').value;
  const res = await fetch(`/api/admin/orders/${id}`, { headers: acAuthHeaders() });
  document.getElementById('acVerbOut').textContent = 'GET -> ' + JSON.stringify(await res.json(), null, 2);
}

async function acVerbDelete() {
  const id = document.getElementById('acVerbId').value;
  const res = await fetch(`/api/admin/orders/${id}`, { method: 'DELETE', headers: acAuthHeaders() });
  document.getElementById('acVerbOut').textContent = 'DELETE -> ' + JSON.stringify(await res.json(), null, 2);
}

async function acTenantOrders() {
  const tenantId = document.getElementById('acTenantId').value;
  const res = await fetch(`/api/tenants/${tenantId}/orders`, { headers: acAuthHeaders() });
  document.getElementById('acTenantOut').textContent = JSON.stringify(await res.json(), null, 2);
}

async function acWhoAmI() {
  const res = await fetch('/api/whoami', { headers: acAuthHeaders() });
  document.getElementById('acTamperOut').textContent = JSON.stringify(await res.json(), null, 2);
}

function acTamperToken() {
  const token = acToken();
  if (!token) {
    document.getElementById('acTamperOut').textContent = 'Log in first.';
    return;
  }
  const decoded = JSON.parse(atob(token));
  decoded.role = 'admin'; // client-side edit of an unsigned token
  const tampered = btoa(JSON.stringify(decoded));
  localStorage.setItem('ac_token', tampered);
  document.getElementById('acTokenOut').textContent = tampered;
  document.getElementById('acTamperOut').textContent =
    'Token tampered locally, role set to admin:\n' + JSON.stringify(decoded, null, 2);
}

async function acForceDelete() {
  const id = document.getElementById('acForceId').value;
  // No Authorization header sent at all — the backend route doesn't check anyway.
  const res = await fetch(`/api/orders/${id}/force`, { method: 'DELETE' });
  document.getElementById('acForceOut').textContent = JSON.stringify(await res.json(), null, 2);
}
