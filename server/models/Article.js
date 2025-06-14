const mongoose = require('mongoose');

const ArticleSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
    },
    content: {
        type: String,
        required: true,
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Reference to the User model
        required: true,
    },
    authorName: { // To easily display author's name without population
        type: String,
        required: true,
    },
    category: {
        type: String,
        enum: ['Hindi Literature', 'Literary Theories', 'Story Reviews', 'DU Study Material'],
        required: true,
    },
    imageUrl: {
        type: String, // Optional: for featured image
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    }
});

ArticleSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('Article', ArticleSchema);