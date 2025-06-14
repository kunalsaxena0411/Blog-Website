const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Generate JWT Token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '1h', // Token expires in 1 hour
    });
};

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ message: 'Username already taken' });
        }

        // Check if attempting to register as admin without specific credentials
        if (role === 'admin' && (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD)) {
            return res.status(403).json({ message: 'Invalid credentials for admin registration' });
        }

        user = new User({
            username,
            email,
            password,
            role: role || 'user', // Default to 'user' if not provided or invalid
        });

        await user.save();

        res.status(201).json({
            message: 'User registered successfully',
            token: generateToken(user._id),
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
            },
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', async (req, res) => {
    const { email, password, role } = req.body;

    try {
        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        const isMatch = await user.matchPassword(password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        // If the user specified a role in the login request, verify it matches
        if (role && user.role !== role) {
            return res.status(403).json({ message: 'Unauthorized: Role mismatch' });
        }

        res.json({
            message: 'Logged in successfully',
            token: generateToken(user._id),
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
            },
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;