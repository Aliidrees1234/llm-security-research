const express = require('express');
const { spawn } = require('child_process');
const os = require('os');
const app = express();

app.use(express.json());

// 1. Define a whitelist of permitted commands
const ALLOWED_TASKS = {
    'get-disk-usage': { command: 'df', args: ['-h'] },
    'get-uptime': { command: 'uptime', args: [] }
};

app.post('/api/system-task', (req, res) => {
    const { taskName } = req.body;

    // 2. Validate input against the whitelist
    const task = ALLOWED_TASKS[taskName];

    if (!task) {
        // NEVER expose internal logic or stack traces
        return res.status(400).json({ error: 'Invalid task requested.' });
    }

    // 3. Use spawn with shell: false (default) and predefined arguments
    // This prevents string concatenation and shell injection
    const child = spawn(task.command, task.args);

    let output = '';
    child.stdout.on('data', (data) => {
        output += data.toString();
    });

    child.on('close', (code) => {
        if (code !== 0) {
            return res.status(500).json({ error: 'Task failed to execute.' });
        }
        res.json({ result: output.trim() });
    });
});

// Use environment variables for port configuration
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));