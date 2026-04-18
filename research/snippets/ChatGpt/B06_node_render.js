const express = require("express");
const app = express();

app.get("/greet", (req, res) => {
    const name = req.query.name;

    res.send(`
        <html>
            <body>
                <h1>Hello ${name}</h1>
            </body>
        </html>
    `);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});

