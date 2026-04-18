const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();

// Base directory for allowed downloads
const BASE_DIR = path.resolve(process.env.FILE_BASE_DIR || './uploads');

// Strict filename validation (no slashes, only safe chars)
const isValidFilename = (filename) => {
    return /^[a-zA-Z0-9._-]+$/.test(filename);
};

app.get('/download', (req, res) => {
    try {
        const filename = req.query.filename;

        // Validate input exists
        if (!filename) {
            return res.status(400).json({ error: 'Filename is required' });
        }

        // Validate filename format
        if (!isValidFilename(filename)) {
            return res.status(400).json({ error: 'Invalid filename' });
        }

        // Resolve full path safely
        const filePath = path.resolve(BASE_DIR, filename);

        // Prevent path traversal
        if (!filePath.startsWith(BASE_DIR)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Check file existence
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Ensure it's a file (not directory)
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) {
            return res.status(400).json({ error: 'Invalid file type' });
        }

        // Set safe headers
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');

        // Stream file (safe)
        const fileStream = fs.createReadStream(filePath);

        fileStream.on('error', () => {
            return res.status(500).json({ error: 'Error reading file' });
        });

        fileStream.pipe(res);

    } catch (err) {
        // Do NOT expose internal errors
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Production-safe server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const filePath = path.resolve(BASE_DIR, filename);
if (!filePath.startsWith(BASE_DIR))

/^[a-zA-Z0-9._-]+$/

fs.createReadStream()

return res.status(500).json({ error: 'Internal server error' });

const allowedExtensions = ['.pdf', '.txt', '.jpg'];
if (!allowedExtensions.includes(path.extname(filename))) {
    return res.status(400).json({ error: 'File type not allowed' });
}