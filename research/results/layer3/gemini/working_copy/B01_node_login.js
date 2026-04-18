const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const router = express.Router();

// This should be in your .env file!
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key';

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Check if user exists (Mock lookup)
        const user = await User.findOne({ email }); 
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // 2. Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // 3. Create JWT Payload
        const payload = {
            id: user._id,
            role: user.role
        };

        // 4. Sign the token
        jwt.sign(
            payload, 
            JWT_SECRET, 
            { expiresIn: '1h' }, 
            (err, token) => {
                if (err) throw err;
                res.json({ 
                    token: `Bearer ${token}`,
                    user: { id: user._id, email: user.email }
                });
            }
        );

    } catch (error) {
        res.status(500).send('Server Error');
    }
});

module.exports = router;

const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    
    if (!authHeader) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Add user info to the request object
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Usage:
// router.get('/profile', authMiddleware, (req, res) => { ... });