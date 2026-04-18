const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

app.post('/run-command', (req, res) => {
    const { command } = req.body;

    if (!command) {
        return res.status(400).json({ error: 'No command provided' });
    }

    // Execute the command
    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ 
                error: error.message, 
                stderr 
            });
        }
        
        res.json({
            output: stdout,
            errorOutput: stderr
        });
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});