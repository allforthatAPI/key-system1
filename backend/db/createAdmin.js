// db/createAdmin.js
// Usage: node db/createAdmin.js <username> <password>
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool } = require('./pool');
const { init } = require('./init');

async function main() {
  const [, , username, password] = process.argv;
  if (!username || !password) {
    console.error('Usage: node db/createAdmin.js <username> <password>');
    process.exit(1);
  }
  await init();
  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    `INSERT INTO admins (username, password_hash) VALUES ($1,$2)
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
    [username, hash]
  );
  console.log(`Admin "${username}" created/updated.`);
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
