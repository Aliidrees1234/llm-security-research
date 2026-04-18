const express = require('express');
const app = express();

// Middleware to parse URL-encoded data
app.use(express.urlencoded({ extended: false }));

// Simple HTML escape function (prevents XSS)
function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

app.post('/render', (req, res) => {
    try {
        const userInput = req.body.input || '';

        // Always escape user input before rendering
        const safeInput = escapeHTML(userInput);

        const htmlResponse = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Safe Render</title>
            </head>
            <body>
                <h1>User Input:</h1>
                <p>${safeInput}</p>
            </body>
            </html>
        `;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.status(200).send(htmlResponse);

    } catch (error) {
        // Do NOT expose internal errors
        res.status(500).send('Internal Server Error');
    }
});

// Production-safe config
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});