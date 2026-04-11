const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Define the directory where your files are stored
const FILES_DIRECTORY = path.join(__dirname, 'uploads');

app.get('/download', (req, res) => {
    // 1. Get the filename from query parameters (e.g., /download?file=report.pdf)
    const fileName = req.query.file;

    if (!fileName) {
        return res.status(400).send('Filename is required.');
    }

    // 2. Security: Prevent "Directory Traversal" attacks
    // This ensures the user can only access files inside the intended folder
    const safeFileName = path.basename(fileName);
    const filePath = path.join(FILES_DIRECTORY, safeFileName);

    // 3. Check if the file exists before attempting download
    if (fs.existsSync(filePath)) {
        res.download(filePath, safeFileName, (err) => {
            if (err) {
                // Handle errors that occur during the streaming process
                console.error("Error during download:", err);
                if (!res.headersSent) {
                    res.status(500).send("Could not download the file.");
                }
            }
        });
    } else {
        res.status(404).send('File not found.');
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});