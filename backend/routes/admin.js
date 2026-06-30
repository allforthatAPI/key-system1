// routes/admin.js
const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../db/pool');
const { requireAdmin } = require('../middleware/auth');
const { generateKey } = require('../utils/keygen');

const router = express.Router();
router.use(requireAdmin);

async function logEvent(keyId, event, detail) {
  await pool.query(
    'INSERT INTO key_logs (key_id, event, detail) VALUES ($1,$2,$3)',
    [keyId, event, detail || null]
  );
}

// ---------- USERS ----------

// GET /api/admin/users  -> full dashboard payload: each user + their keys
router.get('/users', async (req, res) => {
  const usersResult = await pool.query('SELECT id, display_name, username, created_at FROM users ORDER BY created_at DESC');
  const keysResult = await pool.query('SELECT * FROM keys ORDER BY created_at DESC');

  const keysByUser = {};
  for (const k of keysResult.rows) {
    if (!keysByUser[k.user_id]) keysByUser[k.user_id] = [];
    keysByUser[k.user_id].push({
      id: k.id,
      keyString: k.key_string,
      hwid: k.hwid,
      hwidLockedAt: k.hwid_locked_at,
      expiresAt: k.expires_at,
      revoked: k.revoked,
      createdAt: k.created_at,
      lastValidatedAt: k.last_validated_at
    });
  }

  const users = usersResult.rows.map(u => ({
    id: u.id,
    displayName: u.display_name,
    username: u.username,
    createdAt: u.created_at,
    keys: keysByUser[u.id] || []
  }));

  res.json({ users });
});

// POST /api/admin/users  { displayName, username, password }
router.post('/users', async (req, res) => {
  const { displayName, username, password } = req.body || {};
  if (!displayName || !username || !password) {
    return res.status(400).json({ error: 'displayName, username, password are required' });
  }
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = await pool.query(
      'INSERT INTO users (display_name, username, password_hash) VALUES ($1,$2,$3) RETURNING id, display_name, username, created_at',
      [displayName, username, hash]
    );
    res.json({ user: result.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    throw e;
  }
});

// PUT /api/admin/users/:id  { displayName?, username?, password? }
router.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const { displayName, username, password } = req.body || {};
  const fields = [];
  const values = [];
  let i = 1;

  if (displayName) { fields.push(`display_name = $${i++}`); values.push(displayName); }
  if (username) { fields.push(`username = $${i++}`); values.push(username); }
  if (password) { fields.push(`password_hash = $${i++}`); values.push(await bcrypt.hash(password, 12)); }

  if (fields.length === 0) return res.status(400).json({ error: 'Nothing to update' });

  values.push(id);
  await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${i}`, values);
  res.json({ ok: true });
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ---------- KEY GENERATION ----------

// POST /api/admin/keys/generate
// body: { quantity: number, userId?: number, durationDays?: number|null (null = lifetime), prefix?: string }
router.post('/keys/generate', async (req, res) => {
  let { quantity, userId, durationDays, prefix } = req.body || {};
  quantity = parseInt(quantity, 10);
  if (!quantity || quantity < 1 || quantity > 500) {
    return res.status(400).json({ error: 'quantity must be between 1 and 500' });
  }

  const expiresAt = durationDays ? new Date(Date.now() + durationDays * 86400000) : null;
  const created = [];

  for (let n = 0; n < quantity; n++) {
    let key;
    let inserted = false;
    // retry on extremely rare collision
    for (let attempt = 0; attempt < 5 && !inserted; attempt++) {
      key = generateKey(prefix || 'SATURN');
      try {
        const result = await pool.query(
          'INSERT INTO keys (key_string, user_id, expires_at) VALUES ($1,$2,$3) RETURNING id, key_string, expires_at',
          [key, userId || null, expiresAt]
        );
        created.push(result.rows[0]);
        await logEvent(result.rows[0].id, 'generated', `qty batch, user=${userId || 'unassigned'}`);
        inserted = true;
      } catch (e) {
        if (e.code !== '23505') throw e; // unique violation -> retry, else rethrow
      }
    }
  }

  res.json({ keys: created });
});

// ---------- TIME ADJUSTMENT ----------

// POST /api/admin/keys/:id/time   { days: number }  positive = add, negative = reduce
router.post('/keys/:id/time', async (req, res) => {
  const { id } = req.params;
  let { days } = req.body || {};
  days = parseFloat(days);
  if (!days || isNaN(days)) return res.status(400).json({ error: 'days is required and must be non-zero' });

  const result = await pool.query('SELECT * FROM keys WHERE id = $1', [id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'Key not found' });
  const row = result.rows[0];

  const base = row.expires_at && new Date(row.expires_at) > new Date() ? new Date(row.expires_at) : new Date();
  const newExpiry = new Date(base.getTime() + days * 86400000);

  await pool.query('UPDATE keys SET expires_at = $1 WHERE id = $2', [newExpiry, id]);
  await logEvent(id, days > 0 ? 'time_added' : 'time_reduced', `${days} days`);

  res.json({ ok: true, expiresAt: newExpiry });
});

// POST /api/admin/keys/:id/reset-hwid
router.post('/keys/:id/reset-hwid', async (req, res) => {
  const { id } = req.params;
  await pool.query('UPDATE keys SET hwid = NULL, hwid_locked_at = NULL WHERE id = $1', [id]);
  await logEvent(id, 'reset_hwid', null);
  res.json({ ok: true });
});

// POST /api/admin/keys/:id/revoke   { revoked: boolean }
router.post('/keys/:id/revoke', async (req, res) => {
  const { id } = req.params;
  const { revoked } = req.body || {};
  await pool.query('UPDATE keys SET revoked = $1 WHERE id = $2', [!!revoked, id]);
  await logEvent(id, revoked ? 'revoked' : 'unrevoked', null);
  res.json({ ok: true });
});

// DELETE /api/admin/keys/:id
router.delete('/keys/:id', async (req, res) => {
  await pool.query('DELETE FROM keys WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
