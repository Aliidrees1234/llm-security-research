const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const router = express.Router();

// Simulated user DB — replace with real DB queries
const users = [
  {
    id: 1,
    email: "ali@example.com",
    // bcrypt hash of "password123"
    password: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  },
];

// POST /api/auth/login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // 1. Validate input
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  // 2. Find user
  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // 3. Compare password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // 4. Sign JWT
  const token = jwt.sign(
    { id: user.id, email: user.email },  // payload
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );

  res.json({
    message: "Login successful",
    token,
    user: { id: user.id, email: user.email },
  });
});

// POST /api/auth/register
router.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  const exists = users.find((u) => u.email === email);
  if (exists) {
    return res.status(409).json({ message: "Email already in use" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, email, password: hashed };
  users.push(newUser);

  res.status(201).json({ message: "User registered successfully" });
});

module.exports = router;

const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  // Expect: "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // attach user payload to request
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

require("dotenv").config();
const express = require("express");
const authRoutes = require("./routes/auth");
const authMiddleware = require("./middleware/auth");

const app = express();
app.use(express.json());

// Public routes
app.use("/api/auth", authRoutes);

// Protected route example
app.get("/api/profile", authMiddleware, (req, res) => {
  res.json({
    message: "Welcome to your profile!",
    user: req.user,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

