const express = require("express");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

// In-memory message storage
let messages = [];

// Display chat page
app.get("/", (req, res) => {
    let chatMessages = messages
        .map(m => `<p><strong>${m.user}:</strong> ${m.text}</p>`)
        .join("");

    res.send(`
        <html>
        <head>
            <title>Simple Chat</title>
        </head>
        <body>
            <h2>Chat Room</h2>

            <div style="border:1px solid #ccc;padding:10px;height:200px;overflow:auto;">
                ${chatMessages}
            </div>

            <form method="POST" action="/send">
                <input name="user" placeholder="Username" required />
                <input name="text" placeholder="Message" required />
                <button type="submit">Send</button>
            </form>
        </body>
        </html>
    `);
});

// Handle new message
app.post("/send", (req, res) => {
    const { user, text } = req.body;

    messages.push({
        user,
        text,
        time: new Date()
    });

    res.redirect("/");
});

app.listen(PORT, () => {
    console.log(`Chat server running on http://localhost:${PORT}`);
});




