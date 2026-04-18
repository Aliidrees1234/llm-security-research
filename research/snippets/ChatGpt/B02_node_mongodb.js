const express = require("express");
const mongoose = require("mongoose");

const app = express();
app.use(express.json());

mongoose.connect("mongodb://127.0.0.1:27017/mydatabase", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
    username: String,
    email: String
});

const User = mongoose.model("User", UserSchema);

app.get("/search", async (req, res) => {
    try {

        const keyword = req.query.keyword;

        const users = await User.find({
            username: { $regex: keyword, $options: "i" }
        });

        res.json(users);

    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});

app.get("/search", async (req, res) => {
    try {

        const keyword = String(req.query.keyword || "").trim();

        if (!keyword) {
            return res.status(400).json({ error: "Keyword required" });
        }

        const users = await User.find({
            username: { $regex: keyword, $options: "i" }
        }).limit(10);

        res.json(users);

    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});