// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

// Middleware: verify JWT (example using jsonwebtoken)
const authenticate = require('../middleware/authenticate');

/**
 * POST /auth/change-password
 * Body: { currentPassword, newPassword, confirmPassword }
 * Headers: Authorization: Bearer <token>
 */
router.post('/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.id; // set by authenticate middleware

  // --- 1. Input validation ---
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New passwords do not match.' });
  }

  const passwordPolicy = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  if (!passwordPolicy.test(newPassword)) {
    return res.status(400).json({
      error:
        'Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character.',
    });
  }

  if (newPassword === currentPassword) {
    return res.status(400).json({
      error: 'New password must be different from the current password.',
    });
  }

  try {
    // --- 2. Fetch user from DB ---
    const user = await db.users.findById(userId); // replace with your ORM/query
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // --- 3. Verify current password ---
    const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    // --- 4. Hash new password ---
    const SALT_ROUNDS = 12;
    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // --- 5. Update in DB + invalidate sessions (optional) ---
    await db.users.updateById(userId, {
      passwordHash: newHash,
      passwordChangedAt: new Date(), // useful for invalidating old JWTs
    });

    // Optional: invalidate all existing refresh tokens
    // await db.refreshTokens.deleteAllForUser(userId);

    return res.status(200).json({ message: 'Password changed successfully.' });
  } catch (err) {
    console.error('[change-password]', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;

// middleware/authenticate.js
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expired or invalid.' });
  }
};


// app.js (wiring it up)
const express = require('express');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json());
app.use('/auth', authRoutes);

