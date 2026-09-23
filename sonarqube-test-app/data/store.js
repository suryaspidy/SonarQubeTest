/**
 * In-memory "database" shared by the OWASP screens.
 *
 * Kept as plain JS objects (rather than a real DB) so the lab has zero
 * native dependencies and starts instantly. Categories that need SQL
 * Injection (A03) etc. will layer a query-builder on top of this later —
 * for A01 (Broken Access Control) the vulnerabilities are all in the
 * *authorization logic*, not the storage layer.
 *
 * Two tenants (companies) exist, each with users and orders, to support
 * the multi-tenant data-leakage variant.
 */

const users = [
  { id: 1, username: 'alice', password: 'alice123', email: 'alice@acme-corp.example', role: 'user', tenantId: 1, tenantName: 'Acme Corp', bio: 'Loves spreadsheets.', credits: 100 },
  { id: 2, username: 'bob', password: 'bobpass', email: 'bob@globex.example', role: 'user', tenantId: 2, tenantName: 'Globex Inc', bio: 'Coffee enthusiast.', credits: 100 },
  { id: 3, username: 'admin', password: 'Admin@123', email: 'admin@acme-corp.example', role: 'admin', tenantId: 1, tenantName: 'Acme Corp', bio: 'Acme Corp administrator.', credits: 1000 },
  { id: 4, username: 'carol', password: 'carolpass', email: 'carol@globex.example', role: 'user', tenantId: 2, tenantName: 'Globex Inc', bio: 'Runs the Globex support desk.', credits: 100 },
  // "Attacker" account used by the CSRF proof-of-concept page (variant 10) —
  // represents the account a real attacker controls and wants credits sent to.
  { id: 5, username: 'mallory', password: 'mallorypass', email: 'mallory@attacker.example', role: 'user', tenantId: 1, tenantName: 'Acme Corp', bio: 'Just here for the credits.', credits: 0 },
];

const orders = [
  { id: 1, userId: 1, tenantId: 1, item: 'Laptop', amount: 1200, notes: 'Card ending 4242 — billed to Acme Corp' },
  { id: 2, userId: 2, tenantId: 2, item: 'Phone', amount: 800, notes: 'Card ending 1234 — billed to Globex Inc' },
  { id: 3, userId: 3, tenantId: 1, item: 'Server rack', amount: 5000, notes: 'Internal PO#552 — Acme Corp finance' },
  { id: 4, userId: 4, tenantId: 2, item: 'Monitor', amount: 300, notes: 'Card ending 9876 — billed to Globex Inc' },
];

function findUserByUsername(username) {
  return users.find((u) => u.username === username);
}

function findUserById(id) {
  return users.find((u) => u.id === Number(id));
}

function findOrderById(id) {
  return orders.find((o) => o.id === Number(id));
}

function ordersByTenant(tenantId) {
  return orders.filter((o) => o.tenantId === Number(tenantId));
}

function deleteOrder(id) {
  const idx = orders.findIndex((o) => o.id === Number(id));
  if (idx === -1) return false;
  orders.splice(idx, 1);
  return true;
}

// Public-safe projection of a user record (never leak password hashes etc.
// unless a vulnerable endpoint deliberately does so for demonstration).
function safeUser(u) {
  if (!u) return null;
  const { password, ...rest } = u;
  return rest;
}

module.exports = {
  users,
  orders,
  findUserByUsername,
  findUserById,
  findOrderById,
  ordersByTenant,
  deleteOrder,
  safeUser,
};
