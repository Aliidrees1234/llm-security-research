const express = require('express');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const process = require('process');

const app = express();
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Middleware to parse body/query if needed
app.use(express.urlencoded({ extended: true }));

/**
 * PRODUCTION SECURE ENDPOINT
 * Rule: ALWAYS escape/sanitize user input before rendering
 */
app.get('/profile', (req, res) => {
    try {
        const userInput = req.query.username || 'Guest';

        // 1. Sanitize the input to strip out malicious scripts/tags
        // This prevents XSS by neutralizing <script>, onerror, etc.
        const cleanInput = DOMPurify.sanitize(userInput);

        // 2. Render the response
        // Even with sanitization, we wrap it in a safe HTML structure
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head><title>User Profile</title></head>
            <body>
                <h1>Welcome, ${cleanInput}!</h1>
            </body>
            </html>
        `);
    } catch (error) {
        // Rule: NEVER expose stack traces to end users
        console.error('Internal Error:', error.message);
        res.status(500).send('An internal error occurred.');
    }
});

// Rule: NEVER set debug=True (Implicit in Node by environment)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});