const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

app.post("/run-command", (req, res) => {
    const command = req.body.command;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.json({
                error: error.message
            });
        }

        res.json({
            stdout: stdout,
            stderr: stderr
        });
    });
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});

const allowedCommands = {
    list: "ls",
    date: "date"
};

app.post("/run-command", (req, res) => {
    const cmd = allowedCommands[req.body.command];

    if (!cmd) {
        return res.status(400).json({ error: "Command not allowed" });
    }

    exec(cmd, (err, stdout, stderr) => {
        res.json({ stdout, stderr });
    });
});