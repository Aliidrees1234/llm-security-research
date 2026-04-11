const express = require('express');
const router = express.Router();
const db = require('./db-config'); // Your DB connection

// GET /api/products/search
router.get('/search', async (req, res) => {
  try {
    // 1. Destructure filter parameters from the URL
    const { name, category, minPrice, maxPrice } = req.query;

    // 2. Start a base query
    let query = db('products');

    // 3. Conditionally add filters
    if (name) {
      // Use 'ilike' for case-insensitive search in PostgreSQL
      query = query.where('name', 'ilike', `%${name}%`);
    }

    if (category) {
      query = query.where({ category });
    }

    if (minPrice) {
      query = query.where('price', '>=', minPrice);
    }

    if (maxPrice) {
      query = query.where('price', '<=', maxPrice);
    }

    // 4. Execute the query
    const results = await query.select('*').orderBy('created_at', 'desc');

    // 5. Return results
    res.json({
      success: true,
      count: results.length,
      data: results
    });

  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;