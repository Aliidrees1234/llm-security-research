const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

app.post("/fetch", async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: "URL is required" });
        }

        const response = await axios.get(url);

        res.json({
            status: "success",
            data: response.data
        });

    } catch (error) {
        res.status(500).json({
            status: "error",
            message: error.message
        });
    }
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});

