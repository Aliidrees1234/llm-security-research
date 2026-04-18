const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  role: String
});

module.exports = mongoose.model("User", UserSchema);

const express = require("express");
const router = express.Router();
const User = require("./models/User");

router.get("/search", async (req, res) => {
  try {
    const keyword = req.query.q;

    const results = await User.find({
      $or: [
        { name: { $regex: keyword, $options: "i" } },
        { email: { $regex: keyword, $options: "i" } },
        { role: { $regex: keyword, $options: "i" } }
      ]
    });

    res.json(results);

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;

