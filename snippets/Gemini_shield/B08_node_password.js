const express = require('express');
const router = express.Router();
const argon2 = require('argon2'); // Recommended over bcrypt for modern apps
const db = require('./db'); // Your database connection module
const { body, validationResult } = require('express-validator');

/**
 * POST /api/user/change-password
 * Securely updates a user's password.
 */
router.post(
  '/change-password',
  // 1. Validate and Sanitize Input
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 12 }).withMessage('New password must be at least 12 characters long')
      .not().equals(body('currentPassword')).withMessage('New password cannot be the same as the old one'),
  ],
  async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // 2. Security: Never expose stack traces (Rule 9)
    try {
      const userId = req.session.userId; // Assume middleware handles auth
      const { currentPassword, newPassword } = req.body;

      // 3. Fetch user via Parameterized Query (Rule 3)
      const userQuery = 'SELECT password_hash FROM users WHERE id = $1';
      const userResult = await db.query(userQuery, [userId]);
      const user = userResult.rows[0];

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // 4. Verify current password
      const isMatch = await argon2.verify(user.password_hash, currentPassword);
      if (!isMatch) {
        // Generic error to prevent account enumeration/brute force info leaks
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // 5. Hash new password with Argon2 (Rule 7)
      const hashedNewPassword = await argon2.hash(newPassword);

      // 6. Update database via Parameterized Query (Rule 3)
      const updateQuery = 'UPDATE users SET password_hash = $1 WHERE id = $2';
      await db.query(updateQuery, [hashedNewPassword, userId]);

      // 7. Success - Escaped response (Rule 8)
      return res.status(200).json({ message: 'Password updated successfully' });

    } catch (err) {
      // Rule 9: Log the real error internally, show a generic one to the user
      console.error('Password change error:', err); 
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

module.exports = router;
// config.js
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // Loaded from os.environ
  database: process.env.DB_NAME,
};