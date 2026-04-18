// routes/search.js
const express = require("express");
const router = express.Router();
const db = require("../db"); // your DB client (pg, mysql2, mongoose, etc.)

/**
 * GET /api/search
 * Query params:
 *   q         - search term (searches name + description)
 *   category  - filter by category
 *   minPrice  - minimum price filter
 *   maxPrice  - maximum price filter
 *   sortBy    - field to sort by (name | price | createdAt)
 *   order     - asc | desc (default: asc)
 *   page      - page number (default: 1)
 *   limit     - results per page (default: 20, max: 100)
 */
router.get("/search", async (req, res) => {
  try {
    const {
      q = "",
      category,
      minPrice,
      maxPrice,
      sortBy = "createdAt",
      order = "asc",
      page = 1,
      limit = 20,
    } = req.query;

    // ── Validate & sanitize inputs ──────────────────────────────────────────
    const parsedPage = Math.max(1, parseInt(page, 10) || 1);
    const parsedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (parsedPage - 1) * parsedLimit;

    const allowedSortFields = ["name", "price", "createdAt"];
    const safeSortBy = allowedSortFields.includes(sortBy) ? sortBy : "createdAt";
    const safeOrder = order.toLowerCase() === "desc" ? "DESC" : "ASC";

    const parsedMinPrice = minPrice !== undefined ? parseFloat(minPrice) : null;
    const parsedMaxPrice = maxPrice !== undefined ? parseFloat(maxPrice) : null;

    if (
      (parsedMinPrice !== null && isNaN(parsedMinPrice)) ||
      (parsedMaxPrice !== null && isNaN(parsedMaxPrice))
    ) {
      return res.status(400).json({ error: "Invalid price range values." });
    }

    // ── Build query dynamically ─────────────────────────────────────────────
    const conditions = [];
    const values = [];

    if (q.trim()) {
      values.push(`%${q.trim()}%`);
      conditions.push(
        `(LOWER(name) LIKE LOWER($${values.length}) OR LOWER(description) LIKE LOWER($${values.length}))`
      );
    }

    if (category) {
      values.push(category);
      conditions.push(`category = $${values.length}`);
    }

    if (parsedMinPrice !== null) {
      values.push(parsedMinPrice);
      conditions.push(`price >= $${values.length}`);
    }

    if (parsedMaxPrice !== null) {
      values.push(parsedMaxPrice);
      conditions.push(`price <= $${values.length}`);
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // ── Execute queries ─────────────────────────────────────────────────────
    // Total count (for pagination metadata)
    const countResult = await db.query(
      `SELECT COUNT(*) FROM products ${whereClause}`,
      values
    );
    const totalCount = parseInt(countResult.rows[0].count, 10);

    // Paginated data
    values.push(parsedLimit, offset);
    const dataResult = await db.query(
      `SELECT id, name, description, category, price, createdAt
       FROM products
       ${whereClause}
       ORDER BY ${safeSortBy} ${safeOrder}
       LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values
    );

    // ── Send response ───────────────────────────────────────────────────────
    res.json({
      data: dataResult.rows,
      pagination: {
        total: totalCount,
        page: parsedPage,
        limit: parsedLimit,
        totalPages: Math.ceil(totalCount / parsedLimit),
        hasNextPage: parsedPage < Math.ceil(totalCount / parsedLimit),
        hasPrevPage: parsedPage > 1,
      },
    });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

module.exports = router;

// app.js
const express = require("express");
const searchRouter = require("./routes/search");

const app = express();
app.use(express.json());
app.use("/api", searchRouter);

app.listen(3000, () => console.log("Server running on port 3000"));