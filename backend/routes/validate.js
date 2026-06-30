// routes/validate.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db/pool');
const { verifyChecksum } = require('../utils/keygen');

const router = express.Router();

// Throttle hard: validation is the #1 target for brute-forcing key strings.
const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, error: 'Too many attempts. Try again later.' }
});

async function logEvent(keyId, event, detail) {
  await pool.query(
    'INSERT INTO key_logs (key_id, event, detail) VALUES ($1,$2,$3)',
    [keyId, event, detail || null]
  );
}

// POST /api/validate
// body: { key: "SATURN-XXXXX-...-XXXX", hwid: "..." }
//
// Behavior:
//  - Unknown key / bad checksum -> invalid
//  - Revoked -> invalid
//  - Expired -> invalid
//  - No HWID on record yet -> lock this HWID to the key (first activation)
//  - HWID on record differs from supplied HWID -> invalid (locked to another machine)
//  - Otherwise -> valid, return time remaining
router.post('/validate', validateLimiter, async (req, res) => {
  const { key, hwid } = req.body || {};

  if (!key || typeof key !== 'string' || !hwid || typeof hwid !== 'string') {
    return res.status(400).json({ valid: false, error: 'key and hwid are required' });
  }

  if (!verifyChecksum(key)) {
    return res.json({ valid: false, error: 'Malformed key' });
  }

  const result = await pool.query('SELECT * FROM keys WHERE key_string = $1', [key]);
  if (result.rows.length === 0) {
    return res.json({ valid: false, error: 'Key not found' });
  }

  const row = result.rows[0];

  if (row.revoked) {
    await logEvent(row.id, 'rejected_revoked', hwid);
    return res.json({ valid: false, error: 'Key has been revoked' });
  }

  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    await logEvent(row.id, 'rejected_expired', hwid);
    return res.json({ valid: false, error: 'Subscription expired' });
  }

  if (!row.hwid) {
    // First-time activation: lock this HWID permanently to the key.
    await pool.query(
      'UPDATE keys SET hwid = $1, hwid_locked_at = NOW(), last_validated_at = NOW(), last_validated_ip = $2 WHERE id = $3',
      [hwid, req.ip, row.id]
    );
    await logEvent(row.id, 'activated', hwid);
    return res.json({
      valid: true,
      firstActivation: true,
      expiresAt: row.expires_at,
      message: 'Key activated and locked to this device.'
    });
  }

  if (row.hwid !== hwid) {
    await logEvent(row.id, 'rejected_hwid_mismatch', hwid);
    return res.json({ valid: false, error: 'Key is locked to a different device' });
  }

  await pool.query(
    'UPDATE keys SET last_validated_at = NOW(), last_validated_ip = $1 WHERE id = $2',
    [req.ip, row.id]
  );
  await logEvent(row.id, 'validated', hwid);

  return res.json({
    valid: true,
    firstActivation: false,
    expiresAt: row.expires_at
  });
});

module.exports = router;
