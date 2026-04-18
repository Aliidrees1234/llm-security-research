const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory message store
const messages = [
  { id: 1, author: 'System', text: 'Welcome to the chat! Say hello 👋', timestamp: Date.now() - 60000, color: '#6ee7b7' },
];
let nextId = 2;

// GET all messages (supports polling via ?since=lastId)
app.get('/api/messages', (req, res) => {
  const since = parseInt(req.query.since) || 0;
  const filtered = messages.filter(m => m.id > since);
  res.json(filtered);
});

// POST a new message
app.post('/api/messages', (req, res) => {
  const { author, text, color } = req.body;

  if (!author?.trim() || !text?.trim()) {
    return res.status(400).json({ error: 'author and text are required' });
  }
  if (text.length > 500) {
    return res.status(400).json({ error: 'Message too long (max 500 chars)' });
  }

  const message = {
    id: nextId++,
    author: author.trim().slice(0, 30),
    text: text.trim(),
    color: color || '#a78bfa',
    timestamp: Date.now(),
  };

  messages.push(message);
  if (messages.length > 200) messages.shift();

  res.status(201).json(message);
});

// DELETE all messages
app.delete('/api/messages', (req, res) => {
  messages.length = 0;
  nextId = 1;
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`\n  Chat server running → http://localhost:${PORT}\n`);
});