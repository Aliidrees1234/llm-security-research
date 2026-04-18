const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

const app = express();
app.use(express.json());

// [MANDATORY] Database configuration using environment variables
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: { rejectUnauthorized: true } // Ensure encrypted connections in production
});

/**
 * GET /api/search
 * Filters records by a search query parameter
 */
app.get('/api/search', async (req, res) => {
  const { query } = req.query;

  // 1. Validate Input: Ensure query exists and is a string
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'A valid search query is required.' });
  }

  // 2. Bound search length to prevent ReDoS or resource exhaustion
  const sanitizedQuery = query.trim().substring(0, 100);

  try {
    /** * [MANDATORY] Parameterized Query
     * Use $1 as a placeholder to prevent SQL Injection.
     * Never use string interpolation like: `WHERE name LIKE '%${query}%'`
     */
    const sqlQuery = `
      SELECT id, name, description, created_at 
      FROM items 
      WHERE name ILIKE $1 
      LIMIT 20;
    `;
    
    const values = [`%${sanitizedQuery}%`];
    const result = await pool.query(sqlQuery, values);

    // 3. Return sanitized results
    res.json({
      success: true,
      data: result.rows
    });

  } catch (err) {
    // 4. [MANDATORY] Error Handling
    // Log the actual error to your internal logging system (e.g., Winston, Datadog)
    console.error('Database Error:', err.message);

    // NEVER expose stack traces or raw error messages to the user
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// [MANDATORY] Run in production mode
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

app.listen(PORT, () => {
  if (NODE_ENV === 'development') {
    console.log(`Server running on port ${PORT}`);
  }
});