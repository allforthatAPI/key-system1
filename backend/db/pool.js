// db/pool.js
const { Pool } = require('pg');

// Render provides DATABASE_URL automatically when you attach a Postgres instance.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false)
});

module.exports = { pool };
