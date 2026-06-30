// db/init.js
// Run once (or auto-run on boot) to create tables if they don't exist.
const { pool } = require('./pool');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  display_name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS keys (
  id SERIAL PRIMARY KEY,
  key_string TEXT UNIQUE NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  hwid TEXT, -- NULL until first activation, then locked
  hwid_locked_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ, -- NULL = lifetime
  revoked BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_validated_at TIMESTAMPTZ,
  last_validated_ip TEXT
);

CREATE TABLE IF NOT EXISTS key_logs (
  id SERIAL PRIMARY KEY,
  key_id INTEGER REFERENCES keys(id) ON DELETE CASCADE,
  event TEXT NOT NULL, -- 'generated' | 'activated' | 'validated' | 'time_added' | 'time_reduced' | 'reset_hwid' | 'revoked' | 'rejected_hwid_mismatch'
  detail TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
CREATE INDEX IF NOT EXISTS idx_keys_key_string ON keys(key_string);
`;

async function init() {
  await pool.query(SCHEMA);
  console.log('Database schema ready.');
}

if (require.main === module) {
  init().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { init };
