const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();

app.use(express.json());

const url = 'mongodb://localhost:27017';
const client = new MongoClient(url);
const dbName = 'myDatabase';

async function startServer() {
  await client.connect();
  const db = client.db(dbName);
  const collection = db.collection('items');

  // The Endpoint
  app.get('/search', async (req, res) => {
    try {
      // 1. Grab input from query string (e.g., /search?name=Laptop)
      const userInput = req.query.name;

      if (!userInput) {
        return res.status(400).json({ error: 'Search term is required' });
      }

      // 2. Query the database
      // Using an object literal { name: userInput } prevents basic injection
      const result = await collection.findOne({ name: userInput });

      if (!result) {
        return res.status(404).json({ message: 'No item found' });
      }

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  app.listen(3000, () => console.log('Server running on port 3000'));
}

startServer().catch(console.error);

// Mongoose version
const item = await Item.findOne({ name: req.query.name });