const express = require('express');
const router = express.Router();
const Article = require('../models/Article');
const { protect, authorize } = require('../middleware/auth'); // Import middleware

// @route   GET /api/articles
// @desc    Get all articles
// @access  Public
router.get('/', async (req, res) => {
    try {
        const articles = await Article.find().sort({ createdAt: -1 });
        res.json(articles);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/articles/:id
// @desc    Get single article by ID
// @access  Public
router.get('/:id', async (req, res) => {
    try {
        const article = await Article.findById(req.params.id);
        if (!article) {
            return res.status(404).json({ message: 'Article not found' });
        }
        res.json(article);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/articles
// @desc    Create a new article
// @access  Private (Admin only)
router.post('/', protect, authorize('admin'), async (req, res) => {
    const { title, content, category, imageUrl } = req.body;

    try {
        const newArticle = new Article({
            title,
            content,
            category,
            imageUrl,
            author: req.user.id, // Comes from the protect middleware
            authorName: req.user.username, // Store author's username
        });

        const article = await newArticle.save();
        res.status(201).json(article);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   PUT /api/articles/:id
// @desc    Update an article
// @access  Private (Admin only)
router.put('/:id', protect, authorize('admin'), async (req, res) => {
    const { title, content, category, imageUrl } = req.body;

    try {
        let article = await Article.findById(req.params.id);

        if (!article) {
            return res.status(404).json({ message: 'Article not found' });
        }

        // Ensure the admin modifying is the author or allow any admin
        // For simplicity, we'll allow any admin to edit any article.
        // If you want only the original author to edit, add:
        // if (article.author.toString() !== req.user.id) {
        //     return res.status(401).json({ message: 'Not authorized to update this article' });
        // }

        article.title = title || article.title;
        article.content = content || article.content;
        article.category = category || article.category;
        article.imageUrl = imageUrl || article.imageUrl;
        article.updatedAt = Date.now(); // Update the timestamp

        await article.save();
        res.json(article);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   DELETE /api/articles/:id
// @desc    Delete an article
// @access  Private (Admin only)
router.delete('/:id', protect, authorize('admin'), async (req, res) => {
    try {
        const article = await Article.findById(req.params.id);

        if (!article) {
            return res.status(404).json({ message: 'Article not found' });
        }

        // For simplicity, allow any admin to delete any article.
        // If you want only the original author to delete, add:
        // if (article.author.toString() !== req.user.id) {
        //     return res.status(401).json({ message: 'Not authorized to delete this article' });
        // }

        await Article.deleteOne({ _id: req.params.id }); // Use deleteOne for Mongoose 6+
        res.json({ message: 'Article removed' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;