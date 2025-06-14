const express = require('express');
const connectDB = require('./config/db');
const path = require('path');
const app = express();
require('dotenv').config(); // Load environment variables from .env file

// Connect Database
connectDB();

// Init Middleware
// This allows the app to parse JSON bodies from incoming requests
app.use(express.json());

// Serve static files from the 'public' directory
// This line assumes your 'public' directory is one level up from your 'server' directory
app.use(express.static(path.join(__dirname, '../public')));

// Define API Routes
// Using try-catch blocks to better diagnose if route files are problematic
try {
    const authRoutes = require('./routes/auth');
    // Ensure that authRoutes actually exports an Express router instance
    if (typeof authRoutes === 'function') {
        app.use('/api/auth', authRoutes);
        console.log('✅ Auth routes loaded successfully at /api/auth');
    } else {
        console.error('❌ Error: ./routes/auth did not export an Express router. Please check auth.js export.');
    }
} catch (error) {
    console.error('❌ Failed to load auth routes:', error.message);
}

try {
    const articleRoutes = require('./routes/articles');
    // Ensure that articleRoutes actually exports an Express router instance
    if (typeof articleRoutes === 'function') {
        app.use('/api/articles', articleRoutes);
        console.log('✅ Article routes loaded successfully at /api/articles');
    } else {
        console.error('❌ Error: ./routes/articles did not export an Express router. Please check articles.js export.');
    }
} catch (error) {
    console.error('❌ Failed to load article routes:', error.message);
}

// Serve index.html for all other routes (SPA setup)
// This ensures that for any non-API route, your frontend application is served.
app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../public', 'index.html'));
});

// Set the port for the server to listen on
const PORT = process.env.PORT || 5000;

// Start the server
app.listen(PORT, () => console.log(`🚀 Server started on port ${PORT}`));

