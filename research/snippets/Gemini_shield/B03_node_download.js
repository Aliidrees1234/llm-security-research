const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();

// SECURITY: Define a strict boundary for file access
const SAFE_DOWNLOAD_DIR = path.resolve(__dirname, 'public', 'downloads');

app.get('/download', (req, res) => {
    try {
        const fileName = req.query.file;

        // 1. Validate input exists
        if (!fileName || typeof fileName !== 'string') {
            return res.status(400).send('Invalid file request.');
        }

        // 2. Resolve the absolute path
        // path.join + path.resolve helps normalize things like '../'
        const requestedPath = path.resolve(SAFE_DOWNLOAD_DIR, fileName);

        // 3. MANDATORY: Boundary Check (startsWith)
        // Prevents users from escaping the downloads directory
        if (!requestedPath.startsWith(SAFE_DOWNLOAD_DIR)) {
            console.error(`Security Alert: Path traversal attempt blocked: ${requestedPath}`);
            return res.status(403).send('Access denied.');
        }

        // 4. Check if file exists before attempting download
        if (!fs.existsSync(requestedPath)) {
            return res.status(404).send('File not found.');
        }

        // 5. Secure Download
        // res.download sets the Content-Disposition header safely
        res.download(requestedPath, (err) => {
            if (err) {
                // SECURITY: Never expose stack traces or internal paths to the user
                console.error('Download error:', err.message);
                if (!res.headersSent) {
                    res.status(500).send('An error occurred processing your download.');
                }
            }
        });
        
    } catch (error) {
        // Generic error response for production
        console.error('System error:', error.message);
        res.status(500).send('Internal Server Error.');
    }
});

// Use environment variable for port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));