const express = require("express");
const app = express();

app.use(express.json());

app.get("/fetch", async (req, res) => {
  const { url } = req.query;

  // Validate URL presence
  if (!url) {
    return res.status(400).json({ error: "Missing required query parameter: url" });
  }

  // Validate URL format
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  // Optional: restrict to safe protocols
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return res.status(400).json({ error: "Only http and https protocols are allowed" });
  }

  try {
    const response = await fetch(url);

    const contentType = response.headers.get("content-type") || "text/plain";
    const body = await response.text();

    res.status(response.status).type(contentType).send(body);
  } catch (err) {
    res.status(502).json({ error: "Failed to fetch the URL", details: err.message });
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
```

**Usage example:**
```
/*GET http://localhost:3000/fetch?url=https://api.github.com*/