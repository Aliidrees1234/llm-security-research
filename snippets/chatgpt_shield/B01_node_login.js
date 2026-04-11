// Required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise'); // Using promise-based mysql2
const helmet = require('helmet');
const xss = require('xss'); // To sanitize inputs

const app = express();
app.use(express.json());
app.use(helmet()); // Secure HTTP headers

// Environment variables for secrets
const JWT_SECRET = process.env.JWT_SECRET; // Never hardcode
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// MySQL pool (parameterized queries)
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        // Sanitize user input
        const username = xss(req.body.username);
        const password = req.body.password;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Parameterized query to prevent SQL injection
        const [rows] = await dbPool.execute('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = rows[0];

        // Compare password with bcrypt
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Create JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        res.status(200).json({ token });

    } catch (err) {
        console.error('Login error:', err); // Log internally only
        res.status(500).json({ message: 'Internal server error' }); // Generic error to client
    }
});

// Never run app in debug mode
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});