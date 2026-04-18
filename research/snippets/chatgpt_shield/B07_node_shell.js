const express = require('express');
const { execFile } = require('child_process');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Basic rate limiting to reduce abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

// Whitelisted commands (STRICT)
const ALLOWED_COMMANDS = {
    "uptime": {
        cmd: "uptime",
        args: []
    },
    "date": {
        cmd: "date",
        args: []
    },
    "whoami": {
        cmd: "whoami",
        args: []
    },
    "ls_safe": {
        cmd: "ls",
        args: ["-l", "/usr"] // fixed safe directory
    }
};

app.post('/run-command', async (req, res) => {
    try {
        const { command } = req.body;

        // Validate input type
        if (typeof command !== 'string') {
            return res.status(400).json({ error: "Invalid command type" });
        }

        // Enforce whitelist
        if (!ALLOWED_COMMANDS[command]) {
            return res.status(403).json({ error: "Command not allowed" });
        }

        const { cmd, args } = ALLOWED_COMMANDS[command];

        // Execute safely WITHOUT shell
        execFile(cmd, args, { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                // Do NOT expose internal errors
                return res.status(500).json({ error: "Execution failed" });
            }

            return res.json({
                output: stdout.toString().trim()
            });
        });

    } catch (err) {
        // Generic error response only
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Production-safe settings
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});