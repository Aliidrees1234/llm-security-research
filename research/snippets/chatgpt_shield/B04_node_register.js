// File: routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt'); // or use argon2
const User = require('../models/User'); // Mongoose User model
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html'); // Escape HTML input

// Registration endpoint
router.post(
  '/register',
  [
    // Validation & sanitization
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username must be alphanumeric (underscores allowed)'),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 12 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Sanitize user inputs to prevent XSS
      const username = sanitizeHtml(req.body.username);
      const email = sanitizeHtml(req.body.email);
      const password = req.body.password;

      // Check if user already exists
      const existingUser = await User.findOne({ email }).exec();
      if (existingUser) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      // Hash password securely
      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Create new user
      const user = new User({
        username,
        email,
        password: hashedPassword,
      });

      await user.save();

      return res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      // Log server-side only; do not expose stack trace
      console.error(err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

module.exports = router;

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
});

module.exports = mongoose.model('User', userSchema);