const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 3000;

app.get("/download", (req, res) => {
    const fileName = req.query.file;

    if (!fileName) {
        return res.status(400).json({ error: "File name is required" });
    }

    const filePath = path.join(__dirname, "files", fileName);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found" });
    }

    res.download(filePath, fileName, (err) => {
        if (err) {
            console.error(err);
            res.status(500).send("Error downloading file");
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const safeName = path.basename(req.query.file);
const filePath = path.join(__dirname, "files", safeName);