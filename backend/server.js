require("dotenv").config(); // Load environment variables from .env file

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto"); // Import crypto for generating cryptographically secure tokens (used for OTP)
const nodemailer = require("nodemailer"); // Import Nodemailer

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Nodemailer Environment Variables
// UPDATED: Using user's provided email and app password directly here.
// IMPORTANT: In a real application, these should remain in .env and not hardcoded.
const EMAIL_HOST = process.env.EMAIL_HOST || "smtp.gmail.com";
const EMAIL_PORT = process.env.EMAIL_PORT || 587;
const EMAIL_USER = process.env.EMAIL_USER || "choudharrutuja@gmail.com"; // User's email
const EMAIL_PASS = process.env.EMAIL_PASS || "vcddjgxlibmkmbye"; // User's App Password
// FE_BASE_URL is not directly used for OTP reset links (as OTP is entered directly),
// but it's kept here in case it's used for other frontend-related links in your application.
const FE_BASE_URL = process.env.FE_BASE_URL || "http://localhost:3000";

// Create a Nodemailer transporter
let transporter;
if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: false, // Use 'true' for port 465 (SSL), 'false' for other ports like 587 (TLS)
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS, // This should be your App Password for Gmail with 2FA
    },
    tls: {
      // This is important for development environments that might have issues with self-signed certs.
      // In production, you typically want to set rejectUnauthorized to true for better security.
      rejectUnauthorized: false,
    },
  });
  console.log("✅ Nodemailer transporter initialized.");
} else {
  console.warn(
    "⚠️ Nodemailer not fully configured. Email sending will be simulated."
  );
  console.warn(
    "Please set EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS in your .env file for real email functionality."
  );
}

// Function to send email
const sendEmail = async (options) => {
  if (!transporter) {
    console.log(
      "Simulating email send (Nodemailer not fully configured):",
      options
    );
    return; // Do nothing if transporter is not set up
  }

  const mailOptions = {
    from: EMAIL_USER, // Sender address
    to: options.to, // List of receivers
    subject: options.subject, // Subject line
    html: options.html, // HTML body
    text: options.text, // Plain text body (fallback)
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully to ${options.to}`);
  } catch (error) {
    console.error("❌ Error sending email:", error);
    throw new Error(
      "Failed to send email. Check Nodemailer configuration and App Password."
    );
  }
};

// Middleware for security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// Enable CORS for all origins (for development)
app.use(cors());
// Parse JSON request bodies
app.use(express.json());

// MongoDB Connection
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected successfully!"))
  .catch((err) => console.error("❌ MongoDB connection error:", err.message));

// Mongoose Schemas
// User Schema: Defines the structure for user documents
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true }, // User's email, must be unique
    password: { type: String, required: true }, // Hashed password
    isAdmin: { type: Boolean, default: false }, // Flag for administrative privileges
    otp: String, // Field to store the One-Time Password
    otpExpires: Date, // Field to store the expiry time for the OTP
  },
  { timestamps: true } // Adds createdAt and updatedAt timestamps
);

// Pre-save hook to hash password before saving
userSchema.pre("save", async function (next) {
  // Only hash if the password field is modified and it's not empty
  if (this.isModified("password") && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// User Model based on userSchema
const User = mongoose.model("User", userSchema);

// Article Schema: Defines the structure for article documents
const articleSchema = new mongoose.Schema(
  {
    title: { type: String, required: true }, // Title of the article
    author: { type: String, required: true }, // Author's email (stored from user during creation)
    category: { type: String, required: true }, // Category of the article
    content: { type: String, required: true }, // Full content of the article
    userId: {
      type: mongoose.Schema.Types.ObjectId, // Reference to the User who created it
      ref: "User",
      required: true,
    },
  },
  { timestamps: true } // Adds createdAt and updatedAt timestamps
);

// Article Model based on articleSchema
const Article = mongoose.model("Article", articleSchema);

// Admin Initialization Function
// This function creates an admin user if one doesn't exist, or promotes an existing user to admin.
async function initializeAdmin() {
  // Check if admin credentials are provided in environment variables
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.warn("⚠️ ADMIN_EMAIL or ADMIN_PASSWORD not set in .env.");
    return;
  }

  try {
    let admin = await User.findOne({ email: ADMIN_EMAIL });
    if (!admin) {
      // Create new admin user if not found
      admin = new User({
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD, // Password will be hashed by the pre-save hook
        isAdmin: true,
      });
      await admin.save();
      console.log("✅ Admin user created successfully.");
    } else if (!admin.isAdmin) {
      // Promote existing user to admin if they are not already
      admin.isAdmin = true;
      // Note: If the password field is not modified, the pre-save hook won't re-hash it.
      // If you intend to ensure the admin password is always the latest from .env,
      // you might need to explicitly set it here again or handle it differently.
      await admin.save();
      console.log("✅ Existing user promoted to admin.");
    } else {
      console.log("ℹ️ Admin user already exists.");
    }
  } catch (err) {
    console.error("❌ Error initializing admin:", err.message);
  }
}

// Authentication Middleware
// Verifies the JWT token from the 'x-auth-token' header
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header("x-auth-token");
    if (!token)
      return res
        .status(401)
        .json({ message: "No authentication token provided." }); // No token found

    const decoded = jwt.verify(token, JWT_SECRET); // Verify the token
    req.user = await User.findById(decoded.id).select("-password"); // Find user and exclude password
    if (!req.user) return res.status(401).json({ message: "User not found." }); // User not found in DB

    next(); // Proceed to the next middleware/route handler
  } catch (err) {
    console.error("Token verification failed:", err.message);
    res.status(401).json({ message: "Invalid or expired token." }); // Token invalid/expired
  }
};

// Admin Authorization Middleware
// Checks if the authenticated user has admin privileges
const adminMiddleware = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ message: "Admin access required." }); // Forbidden if not admin
  }
  next(); // Proceed if admin
};

// --- Routes ---

/**
 * @route POST /api/auth/signup
 * @desc Register a new user
 * @access Public
 */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Prevent direct signup of the hardcoded admin email
    if (email === ADMIN_EMAIL) {
      return res
        .status(400)
        .json({ message: "Admin email cannot be registered via signup." });
    }

    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exists." });

    user = new User({ email, password }); // Password will be hashed by pre-save hook
    await user.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({ message: "Server error during signup." });
  }
});

/**
 * @route POST /api/auth/login
 * @desc Authenticate user and get token
 * @access Public
 */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    // Check if user exists and password is correct
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials." });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin, email: user.email },
      JWT_SECRET,
      { expiresIn: "365d" } // Token expires in 1 year
    );

    res.status(200).json({
      token,
      isAdmin: user.isAdmin,
      email: user.email,
      message: "Login successful",
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Server error during login." });
  }
});

/**
 * @route POST /api/auth/forgot-password
 * @desc Handle forgot password request (generates and saves OTP, sends email)
 * @access Public
 */
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      // It's good practice not to reveal if an email exists for security reasons.
      // So, we send a generic success message even if the user isn't found.
      return res.status(200).json({
        message:
          "यदि यह ईमेल हमारे रिकॉर्ड में है, तो आपको पासवर्ड रीसेट OTP के साथ एक ईमेल प्राप्त होगा।",
      });
    }

    // Generate a 6-digit numeric OTP
    // This uses Math.random() which is sufficient for non-cryptographic purposes like an OTP for email.
    // crypto.randomBytes is used for more secure tokens like password reset tokens in some older implementations.
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Set OTP and expiry on the user document (e.g., 10 minutes expiry)
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes (milliseconds)

    await user.save();

    // Send the email with the OTP
    try {
      await sendEmail({
        to: user.email,
        subject: "Password Reset OTP for Gamakauaa",
        text:
          `You are receiving this because you (or someone else) have requested a password reset for your account on Gamakauaa.\n\n` +
          `Your One-Time Password (OTP) for password reset is: ${otp}\n\n` +
          `This OTP will expire in 10 minutes.\n\n` +
          `If you did not request this, please ignore this email.\n`,
        html: `
          <div style="font-family: sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
            <div style="background-color: #f4f4f4; padding: 20px; text-align: center; border-bottom: 1px solid #eee;">
              <h1 style="color: #4CAF50; margin: 0;">Gamakauaa Password Reset OTP</h1>
            </div>
            <div style="padding: 30px;">
              <p>नमस्ते ${user.email},</p>
              <p>हमें आपकी पासवर्ड रीसेट अनुरोध प्राप्त हुआ है।</p>
              <p>आपका वन-टाइम पासवर्ड (OTP) है:</p>
              <p style="text-align: center; margin: 25px 0;">
                <strong style="font-size: 24px; color: #3b82f6; background-color: #e0f7fa; padding: 10px 20px; border-radius: 5px; letter-spacing: 2px;">${otp}</strong>
              </p>
              <p>यह OTP 10 मिनट में समाप्त हो जाएगा।</p>
              <p>कृपया इस OTP का उपयोग करके अपना नया पासवर्ड सेट करें।</p>
              <p>यदि आपने इस रीसेट का अनुरोध नहीं किया है, तो कृपया इस ईमेल को अनदेखा करें।</p>
              <p>धन्यवाद,<br/>गामाकौआ टीम</p>
            </div>
            <div style="background-color: #f4f4f4; padding: 20px; text-align: center; border-top: 1px solid #eee; font-size: 0.8em; color: #777;">
              <p>यदि आपको मदद की आवश्यकता है, तो हमसे संपर्क करें।</p>
            </div>
          </div>
        `,
      });
      res.status(200).json({
        message:
          "यदि यह ईमेल हमारे रिकॉर्ड में है, तो आपको पासवर्ड रीसेट OTP के साथ एक ईमेल प्राप्त होगा।",
      });
    } catch (emailError) {
      console.error("❌ Failed to send OTP email:", emailError.message);
      res.status(500).json({
        message: "पासवर्ड रीसेट OTP भेजने में सर्वर त्रुटि हुई।",
      });
    }
  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({
      message: "पासवर्ड रीसेट अनुरोध संसाधित करने में सर्वर त्रुटि हुई।",
    });
  }
});

/**
 * @route POST /api/auth/verify-otp-and-reset-password
 * @desc Verify OTP and reset user's password
 * @access Public
 */
app.post("/api/auth/verify-otp-and-reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "सभी फ़ील्ड आवश्यक हैं।" });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "नया पासवर्ड कम से कम 6 वर्णों का होना चाहिए।" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "उपयोगकर्ता नहीं मिला।" });
    }

    // Check if OTP matches and is not expired
    if (user.otp !== otp || user.otpExpires < Date.now()) {
      // Clear OTP fields to prevent further attempts with invalid/expired OTP
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save(); // Save to clear the invalid OTP
      return res
        .status(400)
        .json({ message: "OTP अमान्य या समाप्त हो गया है।" });
    }

    // Update the user's password and clear the OTP fields
    user.password = newPassword; // The pre-save hook will hash this new password
    user.otp = undefined;
    user.otpExpires = undefined;

    await user.save();

    res.status(200).json({ message: "पासवर्ड सफलतापूर्वक रीसेट किया गया।" });
  } catch (error) {
    console.error("Verify OTP and reset password error:", error.message);
    res.status(500).json({ message: "सर्वर त्रुटि पासवर्ड रीसेट कर रही है।" });
  }
});

/**
 * @route GET /api/articles
 * @desc Get all articles or articles by category
 * @access Public
 */
app.get("/api/articles", async (req, res) => {
  try {
    const { category } = req.query; // Get category from query parameters
    const filter = category ? { category } : {}; // Build filter object
    const articles = await Article.find(filter).sort({ createdAt: -1 }); // Find and sort by creation date
    res.status(200).json(articles);
  } catch (error) {
    console.error("Error fetching articles:", error.message);
    res.status(500).json({ message: "Server error fetching articles." });
  }
});

/**
 * @route GET /api/articles/:id
 * @desc Get a single article by ID
 * @access Public
 */
app.get("/api/articles/:id", async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article)
      return res.status(404).json({ message: "Article not found." }); // Article not found
    res.status(200).json(article);
  } catch (error) {
    console.error("Get article by ID error:", error.message);
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID." }); // Handle invalid MongoDB ID format
    }
    res.status(500).json({ message: "Server error fetching article." });
  }
});

/**
 * @route POST /api/articles
 * @desc Create a new article
 * @access Private (Admin only)
 */
app.post("/api/articles", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { title, category, content } = req.body;
    const author = req.user.email; // Author is the email of the authenticated user
    const userId = req.user._id; // User ID of the authenticated user

    // Validate required fields
    if (!title || !category || !content) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const newArticle = new Article({
      title,
      category,
      content,
      author,
      userId,
    });
    const saved = await newArticle.save(); // Save the new article
    res.status(201).json(saved); // Respond with the created article
  } catch (error) {
    console.error("Error creating article:", error.message);
    res.status(500).json({ message: "Server error creating article." });
  }
});

/**
 * @route PUT /api/articles/:id
 * @desc Update an existing article
 * @access Private (Admin only)
 */
app.put(
  "/api/articles/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { title, category, content } = req.body;

      // Validate required fields
      if (!title || !category || !content) {
        return res.status(400).json({ message: "All fields are required." });
      }

      const updatedArticle = await Article.findByIdAndUpdate(
        req.params.id,
        { title, category, content },
        { new: true } // Return the updated document
      );

      if (!updatedArticle) {
        return res.status(404).json({ message: "Article not found." });
      }

      res.status(200).json(updatedArticle);
    } catch (error) {
      console.error("Error updating article:", error.message);
      if (error.name === "CastError") {
        return res.status(400).json({ message: "Invalid article ID." });
      }
      res.status(500).json({ message: "Server error updating article." });
    }
  }
);

/**
 * @route DELETE /api/articles/:id
 * @desc Delete an article
 * @access Private (Admin only)
 */
app.delete(
  "/api/articles/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const deletedArticle = await Article.findByIdAndDelete(req.params.id);

      if (!deletedArticle) {
        return res.status(404).json({ message: "Article not found." });
      }

      res.status(200).json({ message: "Article deleted successfully." });
    } catch (error) {
      console.error("Error deleting article:", error.message);
      if (error.name === "CastError") {
        return res.status(400).json({ message: "Invalid article ID." });
      }
      res.status(500).json({ message: "Server error deleting article." });
    }
  }
);

/**
 * @route GET /
 * @desc Root endpoint, simple status check
 * @access Public
 */
app.get("/", (req, res) => {
  res.send("API is running!");
});

// Start the server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initializeAdmin(); // Initialize admin user on server start
});
