const express = require("express");
const mongoose = require("mongoose");

const userRoutes = require("./routes/users");

const app = express();
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/mydb")
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("Connection error:", err));

app.use("/api/users", userRoutes);

app.listen(3000, () => console.log("Server running on port 3000"));

const express = require("express");
const { query, validationResult } = require("express-validator");
const User = require("../models/User");

const router = express.Router();

// ── Validation rules ──────────────────────────────────────────────────────────
const searchValidation = [
  query("name").optional().trim().isLength({ max: 100 }).escape(),
  query("email").optional().trim().isEmail().normalizeEmail(),
  query("role").optional().isIn(["admin", "user", "guest"]),
  query("minAge").optional().isInt({ min: 0, max: 120 }).toInt(),
  query("maxAge").optional().isInt({ min: 0, max: 120 }).toInt(),
  query("search").optional().trim().isLength({ max: 100 }).escape(),
  query("page").optional().isInt({ min: 1 }).toInt().default(1),
  query("limit").optional().isInt({ min: 1, max: 100 }).toInt().default(20),
  query("sortBy").optional().isIn(["name", "email", "age"]),
  query("sortOrder").optional().isIn(["asc", "desc"]),
];

// ── GET /api/users/search ─────────────────────────────────────────────────────
router.get("/search", searchValidation, async (req, res) => {
  // 1. Reject invalid input early
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const {
    name, email, role,
    minAge, maxAge,
    search,
    page = 1, limit = 20,
    sortBy = "name", sortOrder = "asc",
  } = req.query;

  try {
    // 2. Build query object dynamically from user input
    const filter = {};

    if (name)  filter.name  = { $regex: name, $options: "i" };   // case-insensitive
    if (email) filter.email = email;                               // exact match
    if (role)  filter.role  = role;

    // Age range filter
    if (minAge !== undefined || maxAge !== undefined) {
      filter.age = {};
      if (minAge !== undefined) filter.age.$gte = minAge;
      if (maxAge !== undefined) filter.age.$lte = maxAge;
    }

    // Full-text search across indexed fields (name + email)
    if (search) {
      filter.$text = { $search: search };
    }

    // 3. Pagination & sorting
    const skip      = (page - 1) * limit;
    const sortDir   = sortOrder === "desc" ? -1 : 1;
    const sortQuery = { [sortBy]: sortDir };

    // 4. Run query + count in parallel
    const [users, total] = await Promise.all([
      User.find(filter)
          .select("-__v")            // exclude internal field
          .sort(sortQuery)
          .skip(skip)
          .limit(limit)
          .lean(),                   // plain JS objects = faster
      User.countDocuments(filter),
    ]);

    // 5. Send structured response
    res.json({
      success: true,
      data: users,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// ── GET /api/users/:id ────────────────────────────────────────────────────────
router.get("/:id", async (req, res) => {
  if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
    return res.status(400).json({ success: false, message: "Invalid user ID" });
  }

  try {
    const user = await User.findById(req.params.id).select("-__v").lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    res.json({ success: false, data: user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

module.exports = router;