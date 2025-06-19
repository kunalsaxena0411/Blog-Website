const Article = require("../models/Article");
const User = require("../models/User");

// @desc    Create a new article (Admin only)
// @route   POST /api/articles
exports.createArticle = async (req, res) => {
  try {
    const { title, category, content } = req.body;
    const userId = req.user._id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const newArticle = new Article({
      title,
      author: user.email,
      category,
      content,
      postedBy: user.email,
      userId: userId,
    });

    const savedArticle = await newArticle.save();
    res.status(201).json(savedArticle);
  } catch (error) {
    console.error("Create article error:", error.message);
    res.status(500).json({ message: "Server error creating article." });
  }
};

// @desc    Get all articles
// @route   GET /api/articles
exports.getArticles = async (req, res) => {
  try {
    const articles = await Article.find().sort({ createdAt: -1 });
    res.status(200).json(articles);
  } catch (error) {
    console.error("Get articles error:", error.message);
    res.status(500).json({ message: "Server error fetching articles." });
  }
};

// @desc    Get single article
// @route   GET /api/articles/:id
exports.getArticle = async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: "Article not found." });
    }
    res.status(200).json(article);
  } catch (error) {
    console.error("Get article error:", error.message);
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID." });
    }
    res.status(500).json({ message: "Server error fetching article." });
  }
};
