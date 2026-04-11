// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 3000;

// Directory where downloadable files are stored
const FILES_DIR = path.join(__dirname, "files");

app.get("/download", (req, res) => {
  const { filename } = req.query;

  // 1. Validate filename param exists
  if (!filename) {
    return res.status(400).json({ error: "Missing required query param: filename" });
  }

  // 2. Sanitize: prevent path traversal attacks (e.g. ../../etc/passwd)
  const sanitized = path.basename(filename);
  const filePath = path.join(FILES_DIR, sanitized);

  // 3. Ensure the resolved path is still inside FILES_DIR
  if (!filePath.startsWith(FILES_DIR + path.sep)) {
    return res.status(400).json({ error: "Invalid filename" });
  }

  // 4. Check file actually exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: `File not found: ${sanitized}` });
  }

  // 5. Stream file to client with Content-Disposition header
  res.download(filePath, sanitized, (err) => {
    if (err && !res.headersSent) {
      console.error("Download error:", err);
      res.status(500).json({ error: "Failed to download file" });
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Try: http://localhost:${PORT}/download?filename=example.pdf`);
});

const ALLOWED_EXT = [".pdf", ".txt", ".csv", ".png", ".jpg"];
if (!ALLOWED_EXT.includes(path.extname(sanitized).toLowerCase())) {
  return res.status(403).json({ error: "File type not allowed" });
}