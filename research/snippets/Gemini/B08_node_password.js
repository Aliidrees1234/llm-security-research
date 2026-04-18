const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

// Assuming you have an authentication middleware to get req.user
const authenticate = require('./middleware/auth'); 

router.post('/change-password', authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id; // From your auth middleware

        // 1. Basic validation
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: "Both password fields are required." });
        }

        // 2. Fetch user from database
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // 3. Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Current password is incorrect." });
        }

        // 4. Hash the new password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // 5. Update database
        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({ message: "Password updated successfully." });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error during password change." });
    }
});

module.exports = router;