require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const xss = require('xss');

const app = express();
app.use(express.json());

// PostgreSQL pool setup (secure, using env vars)
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// Whitelist of allowed search columns to prevent SQL injection
const allowedColumns = ['name', 'email', 'username'];

app.get('/search', async (req, res) => {
  try {
    const { column, query } = req.query;

    // Validate column
    if (!allowedColumns.includes(column)) {
      return res.status(400).json({ error: 'Invalid search column' });
    }

    // Validate and sanitize query
    if (!query || typeof query !== 'string' || query.length > 100) {
      return res.status(400).json({ error: 'Invalid search query' });
    }

    const sanitizedQuery = xss(query);

    // Use parameterized query to prevent SQL injection
    const sql = `SELECT id, name, email, username FROM users WHERE ${column} ILIKE $1 LIMIT 50`;
    const values = [`%${sanitizedQuery}%`];

    const { rows } = await pool.query(sql, values);

    // Escape user data before sending back
    const escapedRows = rows.map(row => ({
      id: row.id,
      name: xss(row.name),
      email: xss(row.email),
      username: xss(row.username),
    }));

    return res.json({ results: escapedRows });
  } catch (err) {
    console.error(err); // Log server-side only
    return res.status(500).json({ error: 'Internal Server Error' }); // No stack trace to user
  }
});

// Always use a secure port and never debug mode in production
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});