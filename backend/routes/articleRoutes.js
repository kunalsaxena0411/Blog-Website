const express = require("express");
const router = express.Router();
const { verifyToken, verifyAdmin } = require("../middlewares/authMiddleware");
const {
  createArticle,
  getArticles,
  getArticle,
} = require("../controllers/articleController");

// Public routes
router.get("/", getArticles);
router.get("/:id", getArticle);

// Protected admin routes
router.post("/", verifyToken, verifyAdmin, createArticle);

module.exports = router;
