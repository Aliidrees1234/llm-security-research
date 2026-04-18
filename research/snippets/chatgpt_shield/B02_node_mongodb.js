// File: routes/user.js
const express = require('express');
const router = express.Router();
const { MongoClient, ObjectId } = require('mongodb');
const escapeHtml = require('escape-html'); // For escaping output to HTML

// Load environment variables securely
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME;

if (!MONGO_URI || !DB_NAME) {
    throw new Error("MongoDB connection environment variables are missing");
}

// Initialize MongoDB client
const client = new MongoClient(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

let db;
client.connect()
    .then(() => {
        db = client.db(DB_NAME);
        console.log("Connected to MongoDB securely");
    })
    .catch(err => {
        console.error("MongoDB connection error:", err);
        process.exit(1); // Fail fast
    });

// Secure endpoint: GET /users/:id
router.get('/:id', async (req, res) => {
    try {
        const userId = req.params.id;

        // Validate input: must be a valid ObjectId
        if (!ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        // Parameterized query using ObjectId
        const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Escape output before sending to client (prevents XSS if rendered in HTML)
        const safeUser = {
            _id: user._id.toString(),
            username: escapeHtml(user.username),
            email: escapeHtml(user.email)
        };

        res.json(safeUser);
    } catch (err) {
        console.error("Unexpected error:", err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;