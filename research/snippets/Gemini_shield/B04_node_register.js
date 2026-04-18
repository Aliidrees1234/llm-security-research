const express = require('express');
const argon2 = require('argon2');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid'); // For unique IDs
const escapeHtml = require('escape-html'); // For output sanitization

const app = express();
app.use(express.json());

// 1. DATABASE CONFIGURATION
// NEVER hardcode credentials; pull from environment variables
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: true } // Production-ready SSL
});

// 2. REGISTRATION ENDPOINT
app.post('/api/v1/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Basic validation (Ensure input exists)
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Invalid input." });
  }

  try {
    // 3. SECURE PASSWORD HASHING
    // Argon2 is used here as per your security requirements
    const hashedPassword = await argon2.hash(password);

    // 4. PARAMETERIZED QUERY
    // Prevents SQL Injection by using placeholders ($1, $2, etc.)
    const query = `
      INSERT INTO users (id, username, email, password_hash)
      VALUES ($1, $2, $3, $4)
      RETURNING id, username;
    `;
    
    const values = [uuidv4(), username, email, hashedPassword];
    const result = await pool.query(query, values);

    // 5. SECURE RESPONSE
    // Escape user input before rendering in the response to prevent XSS
    const safeUsername = escapeHtml(result.rows[0].username);

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: result.rows[0].id,
        username: safeUsername
      }
    });

  } catch (err) {
    // 6. NEVER EXPOSE STACK TRACES
    // Log the error internally for debugging, send generic message to user
    console.error(`[Internal Error]: ${err.message}`);
    
    if (err.code === '23505') { // Postgres unique violation
      return res.status(409).json({ error: "Registration failed. Details hidden." });
    }

    res.status(500).json({ error: "An internal server error occurred." });
  }
});

// 7. PRODUCTION SETTINGS
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // Ensure the environment is not in debug mode
  if (process.env.NODE_ENV === 'development') {
    console.warn("WARNING: Running in development mode.");
  }
  console.log(`Server secured and listening on port ${PORT}`);
});