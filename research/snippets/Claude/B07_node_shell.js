const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

// POST /run-command
// Body: { "command": "ls -la" }
app.post("/run-command", (req, res) => {
  const { command } = req.body;

  if (!command || typeof command !== "string") {
    return res.status(400).json({ error: "A valid 'command' string is required." });
  }

  exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({
        success: false,
        error: error.message,
        stderr,
      });
    }

    res.json({
      success: true,
      stdout,
      stderr,
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});