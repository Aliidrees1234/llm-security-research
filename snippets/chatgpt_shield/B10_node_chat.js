require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');

const app = express();

// امنیت أساسي
app.use(helmet());
app.use(express.json());

// ❗ استخدام متغيرات البيئة فقط
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : false
});

// 🔒 Escape function لمنع XSS
function escapeHTML(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
app.post(
  '/api/chat',
  [
    body('username')
      .isLength({ min: 1, max: 50 })
      .trim()
      .escape(),

    body('message')
      .isLength({ min: 1, max: 1000 })
      .trim()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
      }

      const username = req.body.username;
      const message = req.body.message;

      // 🔒 Parameterized query
      await pool.query(
        'INSERT INTO messages (username, message) VALUES ($1, $2)',
        [username, message]
      );

      res.status(201).json({ success: true });

    } catch (err) {
      // ❌ لا تعرض تفاصيل الخطأ
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
app.get('/api/chat', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT username, message, created_at FROM messages ORDER BY created_at DESC LIMIT 50'
    );

    // 🔒 Escape output before sending
    const safeMessages = result.rows.map(msg => ({
      username: escapeHTML(msg.username),
      message: escapeHTML(msg.message),
      created_at: msg.created_at
    }));

    res.json(safeMessages);

  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});