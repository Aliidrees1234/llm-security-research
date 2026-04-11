const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

app.get('/fetch-url', async (req, res) => {
    const { targetUrl } = req.query;

    // 1. Basic Validation
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL query parameter is required' });
    }

    try {
        // 2. Perform the fetch
        const response = await fetch(targetUrl);

        // 3. Check if the external site responded correctly
        if (!response.ok) {
            return res.status(response.status).json({ 
                error: `External site responded with status: ${response.status}` 
            });
        }

        // 4. Parse and return the data (assuming JSON for this example)
        const data = await response.json();
        res.json(data);

    } catch (error) {
        // Handle invalid URLs or network failures
        res.status(500).json({ 
            error: 'Failed to fetch the URL', 
            details: error.message 
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});