// utils/keygen.js
// Keys are generated as cryptographically random bytes, formatted, and the
// server keeps the source of truth in the DB. We additionally HMAC-sign each
// key so the *format* itself can't be guessed/forged offline, but validity is
// always re-checked server-side against the DB (revocation, expiry, HWID).
const crypto = require('crypto');

const SEGMENTS = 5;
const SEGMENT_LEN = 5;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I ambiguity

function randomSegment(len) {
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) {
    out += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return out;
}

function generateRawKey(prefix = 'SATURN') {
  const segs = [];
  for (let i = 0; i < SEGMENTS; i++) segs.push(randomSegment(SEGMENT_LEN));
  return `${prefix}-${segs.join('-')}`;
}

// HMAC checksum segment appended so tampered/typo'd keys fail fast client-side
// before ever hitting the network (cosmetic UX only — server re-validates regardless).
function withChecksum(rawKey) {
  const secret = process.env.KEY_SIGNING_SECRET;
  if (!secret) throw new Error('KEY_SIGNING_SECRET not set');
  const hmac = crypto.createHmac('sha256', secret).update(rawKey).digest('hex').slice(0, 4).toUpperCase();
  return `${rawKey}-${hmac}`;
}

function verifyChecksum(fullKey) {
  const parts = fullKey.split('-');
  if (parts.length < 2) return false;
  const checksum = parts.pop();
  const rawKey = parts.join('-');
  const secret = process.env.KEY_SIGNING_SECRET;
  const expected = crypto.createHmac('sha256', secret).update(rawKey).digest('hex').slice(0, 4).toUpperCase();
  return crypto.timingSafeEqual(Buffer.from(checksum), Buffer.from(expected));
}

function generateKey(prefix) {
  const raw = generateRawKey(prefix);
  return withChecksum(raw);
}

module.exports = { generateKey, verifyChecksum };
