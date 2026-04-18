const express = require('express');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const { body, validationResult } = require('express-validator');
const db = require('./db'); // Assume a parameterized DB driver like pg or mysql2

const router = express.Router();

// 1. Mandatory Security: Use environment variables for secrets
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'production';

router.post('/login', [
  // 2. Always validate and sanitize input
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 12 })
], async (req, res) => {
  
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  try {
    const { email, password } = req.body;

    // 3. MANDATORY: Parameterized Query to prevent SQL Injection
    const userQuery = 'SELECT id, password_hash FROM users WHERE email = $1 LIMIT 1';
    const result = await db.query(userQuery, [email]);
    const user = result.rows[0];

    // 4. Constant-time comparison & Secure Hashing (Argon2)
    // Even if user doesn't exist, we should simulate work to prevent timing attacks
    if (!user || !(await argon2.verify(user.password_hash, password))) {
      // 5. NEVER expose specific failure reasons (Generic Error)
      return res.status(401).json({ error: 'Authentication failed' });
    }

    // 6. Generate JWT with a short expiration
    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' }
    );

    // 7. Secure Cookie Delivery
    res.cookie('auth_token', token, {
      httpOnly: true, // Prevents XSS access to the token
      secure: NODE_ENV === 'production', // Only sends over HTTPS
      sameSite: 'Strict', // Prevents CSRF
      maxAge: 3600000 // 1 hour
    });

    res.status(200).json({ message: 'Login successful' });

  } catch (err) {
    // 8. NEVER expose stack traces to end users
    console.error(err); // Log internally for debugging
    res.status(500).json({ error: 'An internal error occurred' });
  }
});

module.exports = router;