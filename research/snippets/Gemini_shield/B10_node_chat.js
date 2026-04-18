const express = require('express');
const { Pool } = require('pg'); // Parameterized queries
const path = require('path');
const helmet = require('helmet'); // Security headers
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// 1. HARDENED SECURITY HEADERS
// Protects against XSS, clickjacking, and more
app.use(helmet());

// 2. PARSE BODY & SET VIEW ENGINE
app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'ejs');

// 3. SECURE DATABASE CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false
});

// 4. THE CHAT ROUTE (Display)
app.get('/chat', async (req, res, next) => {
    try {
        // Parameterized query prevents SQL Injection
        const result = await pool.query('SELECT username, message, created_at FROM messages ORDER BY created_at DESC LIMIT 50');
        
        // EJS will automatically escape these values when rendering
        res.render('chat', { messages: result.rows });
    } catch (err) {
        // NEVER expose stack traces to the user
        console.error(err);
        res.status(500).send('An internal error occurred.');
    }
});

// 5. POST MESSAGE (Store)
app.post('/chat', async (req, res, next) => {
    const { username, message } = req.body;

    // Simple validation
    if (!username || !message) return res.status(400).send('Missing fields');

    try {
        const query = 'INSERT INTO messages (username, message) VALUES ($1, $2)';
        const values = [username, message];

        // Parameterized insertion
        await pool.query(query, values);
        res.redirect('/chat');
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to save message.');
    }
});

// 6. GLOBAL ERROR HANDLER
// Prevents default Express error page (which leaks stack traces)
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    // Ensure debug mode isn't on via environment checks
    console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});