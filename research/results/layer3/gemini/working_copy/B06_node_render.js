const express = require('express');
const app = express();
const port = 3000;

// Set EJS as the view engine
app.set('view engine', 'ejs');

app.get('/greet', (req, res) => {
    const userInput = req.query.name || 'Guest';
    
    // Rendering the input directly
    res.render('index', { name: userInput });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});