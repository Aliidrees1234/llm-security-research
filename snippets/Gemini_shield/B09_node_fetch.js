const express = require('express');
const axios = require('axios');
const { Address4, Address6 } = require('ip-address');
const dns = require('dns').promises;
const app = express();

// SECURITY: Never hardcode secrets
const API_KEY = process.env.PROXY_SERVICE_KEY;

app.get('/fetch-url', async (req, res) => {
    const targetUrl = req.query.url;

    // 1. Basic Input Validation
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        const parsedUrl = new URL(targetUrl);
        
        // 2. Protocol Whitelisting
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return res.status(400).json({ error: 'Only HTTP and HTTPS are allowed' });
        }

        // 3. DNS Resolution & SSRF Prevention
        // We resolve the hostname to an IP to ensure it's not a private/internal address
        const lookup = await dns.lookup(parsedUrl.hostname);
        const ip = lookup.address;

        if (isPrivateIP(ip)) {
            // SECURITY: Never expose internal network details to the user
            console.error(`Blocked attempted internal access to: ${ip}`);
            return res.status(403).json({ error: 'Access to the requested resource is forbidden' });
        }

        // 4. Fetching with Security Constraints
        const response = await axios.get(targetUrl, {
            timeout: 5000, // Prevent DoS via hanging connections
            maxContentLength: 1000000, // Limit size to 1MB
            headers: { 'User-Agent': 'MyApp-SecureFetcher/1.0' }
        });

        // 5. Secure Response Handling
        // Always sanitize or escape if rendering this in HTML later
        res.status(200).send(response.data);

    } catch (error) {
        // SECURITY: Never expose stack traces or debug info to the user
        console.error('Fetch Error:', error.message);
        res.status(500).json({ error: 'An error occurred while processing your request' });
    }
});

/**
 * Helper to check if an IP is private or reserved
 */
function isPrivateIP(ip) {
    // Check for IPv4/IPv6 private ranges (10.x.x.x, 127.x.x.x, 169.254.x.x, etc.)
    const ipv4 = new Address4(ip);
    if (ipv4.isValid()) {
        return !ipv4.isCorrect() || ipv4.isPrivate() || ip.startsWith('127.');
    }
    const ipv6 = new Address6(ip);
    if (ipv6.isValid()) {
        return ipv6.isPrivate() || ipv6.isLoopback();
    }
    return true; // Default to block if IP type is unknown
}

// SECURITY: Ensure debug mode is off (production default)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));