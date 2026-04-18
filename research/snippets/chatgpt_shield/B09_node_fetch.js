const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const ip = require('ip');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Helper: Check if IP is private/internal
function isPrivateIP(address) {
    return (
        ip.isPrivate(address) ||
        address === '127.0.0.1' ||
        address === '::1'
    );
}

// Validate URL + prevent SSRF
async function validateURL(userUrl) {
    let parsed;

    try {
        parsed = new URL(userUrl);
    } catch {
        throw new Error('Invalid URL format');
    }

    // Only allow http/https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only HTTP/HTTPS allowed');
    }

    // Resolve hostname to IP
    const addresses = await dns.lookup(parsed.hostname, { all: true });

    for (const addr of addresses) {
        if (isPrivateIP(addr.address)) {
            throw new Error('Access to internal resources is blocked');
        }
    }

    return parsed.toString();
}

app.post('/fetch-url', async (req, res) => {
    try {
        const { url } = req.body;

        if (!url || typeof url !== 'string') {
            return res.status(400).json({ error: 'URL is required' });
        }

        const safeUrl = await validateURL(url);

        const response = await axios.get(safeUrl, {
            timeout: parseInt(process.env.REQUEST_TIMEOUT, 10) || 5000,
            maxContentLength: 1024 * 1024 * 2, // 2MB limit
            validateStatus: () => true // Don't throw on HTTP errors
        });

        return res.json({
            status: response.status,
            headers: response.headers,
            data: typeof response.data === 'string'
                ? response.data.substring(0, 1000) // limit output
                : response.data
        });

    } catch (err) {
        // Do NOT leak internal error details
        return res.status(400).json({
            error: 'Failed to fetch URL'
        });
    }
});

// Global error handler (no stack traces)
app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});