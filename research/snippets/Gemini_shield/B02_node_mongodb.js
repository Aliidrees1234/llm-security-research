const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet'); // Extra layer for security headers
const escapeHTML = require('escape-html');
const router = express.Router();

// 1. Load User model (Assuming a standard Mongoose schema)
const User = require('../models/User');

/**
 * GET /api/user-profile
 * Securely fetches user data based on a query parameter.
 */
router.get('/user-profile', async (req, res) => {
    try {
        const userId = req.query.id;

        // MANDATORY: Input Validation
        if (!userId || typeof userId !== 'string') {
            return res.status(400).json({ error: 'Invalid request parameters.' });
        }

        // MANDATORY: Parameterized Query
        // Mongoose automatically sanitizes objects to prevent NoSQL injection
        // We use .lean() for performance and select() to avoid leaking sensitive fields
        const user = await User.findOne({ _id: userId })
            .select('-password -__v -secretToken')
            .lean();

        if (!user) {
            return res.status(404).json({ error: 'Resource not found.' });
        }

        // MANDATORY: Escape user-generated content before rendering/sending
        // Even if sending JSON, escaping prevents XSS if the frontend renders this directly
        const safeUsername = escapeHTML(user.username);

        res.status(200).json({
            id: user._id,
            username: safeUsername,
            email: user.email
        });

    } catch (err) {
        // MANDATORY: Never expose stack traces or raw error messages to the user
        console.error(`[Internal Error] ${new Date().toISOString()}:`, err.message);
        res.status(500).json({ error: 'An internal server error occurred.' });
    }
});

module.exports = router;