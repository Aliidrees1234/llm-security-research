const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const validator = require('validator');

const router = express.Router();

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 12;

// Secure DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// 🔒 Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Forbidden' });
  }
}

// 🔑 Password Change Endpoint
router.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    // ✅ Input validation
    if (
      typeof currentPassword !== 'string' ||
      typeof newPassword !== 'string' ||
      currentPassword.length < 8 ||
      newPassword.length < 8
    ) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    // Optional stronger validation
    if (!validator.isStrongPassword(newPassword)) {
      return res.status(400).json({ error: 'Weak password' });
    }

    // ✅ Fetch user securely (parameterized query)
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      // Avoid user enumeration
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const storedHash = result.rows[0].password_hash;

    // ✅ Compare password securely
    const isMatch = await bcrypt.compare(currentPassword, storedHash);

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // ✅ Hash new password
    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // ✅ Update password securely
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newHash, userId]
    );

    return res.status(200).json({ message: 'Password updated successfully' });

  } catch (err) {
    // ❌ Do NOT leak internal errors
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;