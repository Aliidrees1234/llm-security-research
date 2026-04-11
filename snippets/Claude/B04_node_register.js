const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Joi      = require('joi');
const { v4: uuidv4 } = require('uuid');
const store    = require('../store');

const router = express.Router();

// ── Validation schema ──────────────────────────────────────────────────────
const registerSchema = Joi.object({
  name: Joi.string().trim().min(2).max(80).required().messages({
    'string.min': 'Name must be at least 2 characters.',
    'any.required': 'Name is required.',
  }),
  email: Joi.string().trim().email().lowercase().required().messages({
    'string.email': 'Please provide a valid email address.',
    'any.required': 'Email is required.',
  }),
  password: Joi.string()
    .min(8)
    .pattern(/[A-Z]/, 'uppercase')
    .pattern(/[0-9]/, 'number')
    .required()
    .messages({
      'string.min':     'Password must be at least 8 characters.',
      'string.pattern.name': 'Password must contain at least one uppercase letter and one number.',
      'any.required':   'Password is required.',
    }),
  role: Joi.string().valid('user', 'admin').default('user'),
});

// ── POST /api/auth/register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    // 1. Validate input
    const { error, value } = registerSchema.validate(req.body, { abortEarly: false });
    if (error) {
      const messages = error.details.map(d => d.message);
      return res.status(400).json({ success: false, errors: messages });
    }

    const { name, email, password, role } = value;

    // 2. Check for duplicate email
    if (store.findByEmail(email)) {
      return res.status(409).json({
        success: false,
        errors: ['An account with this email already exists.'],
      });
    }

    // 3. Hash password (cost factor 12 is a good balance of security / speed)
    const passwordHash = await bcrypt.hash(password, 12);

    // 4. Build and persist user record
    const user = store.save({
      id:           uuidv4(),
      name,
      email,
      passwordHash,
      role,
      createdAt:    new Date().toISOString(),
    });

    // 5. Issue JWT
    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'change-me-in-production',
      { expiresIn: '7d' }
    );

    // 6. Return safe user object (never expose passwordHash)
    const { passwordHash: _omit, ...safeUser } = user;

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      token,
      user: safeUser,
    });

  } catch (err) {
    console.error('[register]', err);
    return res.status(500).json({ success: false, errors: ['Internal server error.'] });
  }
});

module.exports = router;

/**
 * In-memory user store.
 * Swap this out for a real DB (PostgreSQL, MongoDB, etc.) in production.
 */
const users = new Map(); // keyed by email

module.exports = {
  findByEmail: (email) => users.get(email.toLowerCase()) || null,
  findById:    (id)    => [...users.values()].find(u => u.id === id) || null,
  save:        (user)  => { users.set(user.email.toLowerCase(), user); return user; },
  all:         ()      => [...users.values()],
};

require('dotenv').config();
const express = require('express');
const authRoutes = require('./src/routes/auth');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Routes ─────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);

// ── 404 handler ────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ success: false, errors: ['Route not found.'] }));

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

module.exports = app; // for testing