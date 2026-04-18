const express = require('express');
const bcrypt = require('bcryptjs');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Simulated database (In a real app, use PostgreSQL, MongoDB, etc.)
const users = [];

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 1. Basic Validation
        if (!username || !email || !password) {
            return res.status(400).json({ message: "Please provide all fields." });
        }

        // 2. Check if user already exists
        const userExists = users.find(user => user.email === email);
        if (userExists) {
            return res.status(400).json({ message: "User already exists." });
        }

        // 3. Hash the password
        // The '10' is the salt rounds (cost factor)
        const hashedPassword = await bcrypt.hash(password, 10);

        // 4. Store user data
        const newUser = {
            id: Date.now(), // Simple ID generation
            username,
            email,
            password: hashedPassword
        };

        users.push(newUser);

        // 5. Respond (Don't send the password back!)
        res.status(201).json({
            message: "User registered successfully",
            user: { id: newUser.id, username: newUser.username, email: newUser.email }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));