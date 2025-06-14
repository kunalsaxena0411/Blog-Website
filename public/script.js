document.addEventListener("DOMContentLoaded", () => {
  const BASE_API_URL = "http://localhost:5000/api"; // Your backend API base URL

  // --- Utility Functions ---

  // Function to open a modal
  window.openModal = (modalId) => {
    document.getElementById(modalId).classList.add("open");
  };

  // Function to close a modal
  window.closeModal = (modalId) => {
    document.getElementById(modalId).classList.remove("open");
  };

  // Function to show messages (success/error)
  const showMessage = (message, type) => {
    const messageContainer = document.getElementById("messageContainer");
    const messageDiv = document.createElement("div");
    messageDiv.classList.add(
      type === "success" ? "success-message" : "error-message"
    );
    messageDiv.textContent = message;
    messageContainer.appendChild(messageDiv);

    setTimeout(() => {
      messageDiv.remove();
    }, 4000); // Message disappears after 4 seconds
  };

  // Function to decode JWT token
  function parseJwt(token) {
    try {
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map(function (c) {
            return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
          })
          .join("")
      );
      return JSON.parse(jsonPayload);
    } catch (e) {
      console.error("Error parsing JWT:", e);
      return null;
    }
  }

  // Check authentication status and update UI
  function checkAuthStatus() {
    const token = localStorage.getItem("jwtToken");
    const userProfileDropdown = document.getElementById("userProfileDropdown");
    const userEmailDisplay = document.getElementById("userEmailDisplay");
    const postContentLink = document.getElementById("postContentLink");
    const loginBtn = document.getElementById("loginBtn");
    const signupBtn = document.getElementById("signupBtn");
    const authButtons = document.getElementById("authButtons");

    // Mobile elements
    const mobileUserProfileDropdown = document.getElementById(
      "mobileUserProfileDropdown"
    );
    const mobileUserEmailDisplay = document.getElementById(
      "mobileUserEmailDisplay"
    );
    const mobilePostContentLink = document.getElementById(
      "mobilePostContentLink"
    );
    const mobileLoginBtn = document.getElementById("mobileLoginBtn");
    const mobileSignupBtn = document.getElementById("mobileSignupBtn");
    const mobileAuthButtons = document.getElementById("mobileAuthButtons");

    if (token) {
      const decodedToken = parseJwt(token);
      if (decodedToken && decodedToken.id) {
        // User is logged in
        userEmailDisplay.textContent = decodedToken.email;
        userProfileDropdown.classList.remove("hidden");
        authButtons.classList.add("hidden");

        mobileUserEmailDisplay.textContent = decodedToken.email;
        mobileUserProfileDropdown.classList.remove("hidden");
        mobileAuthButtons.classList.add("hidden");

        // Check if user is admin
        if (decodedToken.role === "admin") {
          postContentLink.classList.remove("hidden");
          mobilePostContentLink.classList.remove("hidden");
        } else {
          postContentLink.classList.add("hidden");
          mobilePostContentLink.classList.add("hidden");
        }
      }
    } else {
      // User is not logged in
      userProfileDropdown.classList.add("hidden");
      authButtons.classList.remove("hidden");
      postContentLink.classList.add("hidden");

      mobileUserProfileDropdown.classList.add("hidden");
      mobileAuthButtons.classList.remove("hidden");
      mobilePostContentLink.classList.add("hidden");
    }
  }

  // --- Event Listeners for Authentication and Content Posting ---

  // Login Button Click
  document.getElementById("loginBtn").addEventListener("click", () => {
    openModal("loginModal");
  });
  document.getElementById("mobileLoginBtn").addEventListener("click", () => {
    openModal("loginModal");
  });

  // Signup Button Click
  document.getElementById("signupBtn").addEventListener("click", () => {
    openModal("signupModal");
  });
  document.getElementById("mobileSignupBtn").addEventListener("click", () => {
    openModal("signupModal");
  });

  // Post Content Link Click (Admin Only)
  document.getElementById("postContentLink").addEventListener("click", () => {
    openModal("postContentModal");
  });
  document
    .getElementById("mobilePostContentLink")
    .addEventListener("click", () => {
      openModal("postContentModal");
    });

  // Logout Button Click
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.removeItem("jwtToken");
    checkAuthStatus();
    showMessage("आप सफलतापूर्वक लॉग आउट हो गए हैं।", "success");
    // Optionally redirect to home or reload articles
    loadArticles();
  });
  document.getElementById("mobileLogoutBtn").addEventListener("click", () => {
    localStorage.removeItem("jwtToken");
    checkAuthStatus();
    showMessage("आप सफलतापूर्वक लॉग आउट हो गए हैं।", "success");
    loadArticles();
  });

  // Login Form Submission
  document.getElementById("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    try {
      const response = await fetch(`${BASE_API_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem("jwtToken", data.token); // Store the JWT
        showMessage("लॉग इन सफल!", "success");
        closeModal("loginModal");
        checkAuthStatus(); // Update UI
        loadArticles(); // Reload articles if necessary
      } else {
        showMessage(data.message || "लॉग इन विफल।", "error");
      }
    } catch (error) {
      console.error("Login error:", error);
      showMessage("लॉग इन के दौरान एक त्रुटि हुई।", "error");
    }
  });

  // Signup Form Submission
  document
    .getElementById("signupForm")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("signupUsername").value;
      const email = document.getElementById("signupEmail").value;
      const password = document.getElementById("signupPassword").value;

      try {
        const response = await fetch(`${BASE_API_URL}/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ username, email, password }),
        });

        const data = await response.json();

        if (response.ok) {
          showMessage("साइन अप सफल! अब आप लॉग इन कर सकते हैं।", "success");
          closeModal("signupModal");
          // Optionally auto-fill login form or open login modal
          document.getElementById("loginEmail").value = email;
          openModal("loginModal");
        } else {
          showMessage(data.message || "साइन अप विफल।", "error");
        }
      } catch (error) {
        console.error("Signup error:", error);
        showMessage("साइन अप के दौरान एक त्रुटि हुई।", "error");
      }
    });

  // Post Article Form Submission
  document
    .getElementById("postArticleForm")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = document.getElementById("articleTitle").value;
      const category = document.getElementById("articleCategory").value;
      const imageUrl = document.getElementById("articleImageUrl").value;
      const content = document.getElementById("articleContent").innerHTML; // Get HTML content

      const token = localStorage.getItem("jwtToken");
      if (!token) {
        showMessage("सामग्री पोस्ट करने के लिए कृपया लॉग इन करें।", "error");
        return;
      }

      try {
        const response = await fetch(`${BASE_API_URL}/articles`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ title, content, category, imageUrl }),
        });

        const data = await response.json();

        if (response.ok) {
          showMessage("लेख सफलतापूर्वक पोस्ट किया गया!", "success");
          closeModal("postContentModal");
          document.getElementById("postArticleForm").reset(); // Clear form
          document.getElementById("articleContent").innerHTML = ""; // Clear rich text editor
          loadArticles(); // Reload articles to show the new one
        } else {
          showMessage(data.message || "लेख पोस्ट करने में विफल।", "error");
        }
      } catch (error) {
        console.error("Post article error:", error);
        showMessage("लेख पोस्ट करते समय एक त्रुटि हुई।", "error");
      }
    });

  // Rich Text Editor functionality
  document.querySelectorAll(".editor-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const command = button.dataset.command;
      const editor = document.getElementById("articleContent");
      if (!editor) return;

      if (command === "createLink") {
        const url = prompt("लिंक URL दर्ज करें:");
        if (url) {
          document.execCommand(command, false, url);
        }
      } else if (["h1", "h2", "p"].includes(command)) {
        document.execCommand("formatBlock", false, `<${command}>`);
      } else {
        document.execCommand(command, false, null);
      }
      editor.focus();
    });
  });

  // --- Article Loading and Display ---

  const articlesContainer = document.getElementById("articlesContainer");
  const loadingSpinner = document.getElementById("loadingSpinner");
  const noArticlesMessage = document.getElementById("noArticlesMessage");

  async function loadArticles(searchTerm = "") {
    loadingSpinner.style.display = "block";
    articlesContainer.innerHTML = "";
    noArticlesMessage.classList.add("hidden");

    let url = `${BASE_API_URL}/articles`;
    if (searchTerm) {
      url += `?search=${encodeURIComponent(searchTerm)}`;
    }

    try {
      const response = await fetch(url);
      const articles = await response.json();

      loadingSpinner.style.display = "none";

      if (articles.length > 0) {
        articles.forEach((article) => {
          const articleCard = document.createElement("div");
          articleCard.classList.add(
            "content-overlay",
            "p-6",
            "rounded-lg",
            "shadow-lg",
            "transform",
            "hover:scale-105",
            "transition",
            "duration-300",
            "ease-in-out",
            "flex",
            "flex-col"
          );

          articleCard.innerHTML = `
                        ${
                          article.imageUrl
                            ? `<img src="${article.imageUrl}" alt="${article.title}" class="w-full h-48 object-cover rounded-md mb-4"/>`
                            : ""
                        }
                        <h3 class="text-xl font-bold mb-2 text-gray-900">${
                          article.title
                        }</h3>
                        <p class="text-gray-600 text-sm mb-3">लेखक: ${
                          article.authorName
                        } | श्रेणी: ${article.category}</p>
                        <div class="text-gray-700 text-base flex-grow overflow-hidden text-ellipsis" style="display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;">
                            ${article.content}
                        </div>
                        <button class="mt-4 bg-blue-600 text-white px-4 py-2 rounded-full hover:bg-blue-700 transition duration-300 self-end read-more-btn" data-id="${
                          article._id
                        }">और पढ़ें</button>
                    `;
          articlesContainer.appendChild(articleCard);
        });

        // Attach event listeners to "Read More" buttons
        document.querySelectorAll(".read-more-btn").forEach((button) => {
          button.addEventListener("click", (e) => {
            const articleId = e.target.dataset.id;
            loadArticleDetail(articleId);
          });
        });
      } else {
        noArticlesMessage.classList.remove("hidden");
      }
    } catch (err) {
      console.error("Failed to load articles:", err);
      loadingSpinner.style.display = "none";
      noArticlesMessage.classList.remove("hidden");
      noArticlesMessage.textContent =
        "लेख लोड करते समय एक त्रुटि हुई। कृपया बाद में पुनः प्रयास करें।";
    }
  }

  // Function to load and display individual article detail
  async function loadArticleDetail(articleId) {
    const articleDetailModal = document.getElementById("articleDetailModal");
    const articleDetailTitle = document.getElementById("articleDetailTitle");
    const articleDetailAuthor = document.getElementById("articleDetailAuthor");
    const articleDetailCategory =
      document.getElementById("articleDetailCategory");
    const articleDetailImage = document.getElementById("articleDetailImage");
    const articleDetailContent = document.getElementById(
      "articleDetailContent"
    );

    try {
      const response = await fetch(`${BASE_API_URL}/articles/${articleId}`);
      const article = await response.json();

      if (response.ok) {
        articleDetailTitle.textContent = article.title;
        articleDetailAuthor.textContent = article.authorName;
        articleDetailCategory.textContent = article.category;
        articleDetailContent.innerHTML = article.content; // Use innerHTML for rich text

        if (article.imageUrl) {
          articleDetailImage.src = article.imageUrl;
          articleDetailImage.style.display = "block";
        } else {
          articleDetailImage.style.display = "none";
        }

        openModal("articleDetailModal");
      } else {
        showMessage(article.message || "लेख लोड नहीं हो सका।", "error");
        articleDetailContent.innerHTML = `<p class="text-red-500">लेख लोड नहीं हो सका।</p>`;
      }
    } catch (error) {
      console.error("Error loading article detail:", error);
      showMessage("लेख विवरण लोड करते समय एक त्रुटि हुई।", "error");
      articleDetailContent.innerHTML = `<p class="text-red-500">लेख लोड नहीं हो सका।</p>`;
    }
  }

  // Search functionality
  const searchInput = document.getElementById("searchInput");
  const searchButton = document.getElementById("searchButton");

  searchButton.addEventListener("click", () => {
    const searchTerm = searchInput.value.trim();
    loadArticles(searchTerm);
  });

  searchInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      const searchTerm = searchInput.value.trim();
      loadArticles(searchTerm);
    }
  });

  // --- Header Scroll Effect ---
  const header = document.querySelector("header");
  window.addEventListener("scroll", () => {
    if (window.scrollY > 50) {
      header.classList.add("scrolled");
    } else {
      header.classList.remove("scrolled");
    }
  });

  // --- Mobile Menu Toggle ---
  const mobileMenuButton = document.getElementById("mobileMenuButton");
  const mobileMenu = document.getElementById("mobileMenu");

  mobileMenuButton.addEventListener("click", () => {
    mobileMenu.classList.toggle("hidden");
  });

  // --- Back to Top Button ---
  const backToTopBtn = document.getElementById("backToTopBtn");

  const toggleBackToTopButton = () => {
    if (window.scrollY > 300) {
      backToTopBtn.classList.add("opacity-100", "scale-100");
      backToTopBtn.classList.remove("opacity-0", "scale-0");
    } else {
      backToTopBtn.classList.add("opacity-0", "scale-0");
      backToTopBtn.classList.remove("opacity-100", "scale-100");
    }
  };

  window.addEventListener("scroll", toggleBackToTopButton);
  backToTopBtn.addEventListener("click", () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  });

  // Contact Us Modal functionality
  const contactUsLink = document.getElementById("contactUsLink");
  const mobileContactUsLink = document.getElementById("mobileContactUsLink");
  const contactUsModal = document.getElementById("contactUsModal");
  const heroContactUsLink = document.getElementById("heroContactUsLink");

  if (contactUsLink) {
    contactUsLink.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("contactUsModal");
    });
  }

  if (mobileContactUsLink) {
    mobileContactUsLink.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("contactUsModal");
    });
  }

  if (heroContactUsLink) {
    heroContactUsLink.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("contactUsModal");
    });
  }

  // Join Now Button in CTA section
  const joinNowBtn = document.getElementById("joinNowBtn");
  if (joinNowBtn) {
    joinNowBtn.addEventListener("click", function () {
      openModal("signupModal"); // Open signup modal when "Join Now" is clicked
    });
  }

  // Contact Form Submission (assuming a backend endpoint '/api/contact')
  document
    .getElementById("contactForm")
    .addEventListener("submit", async function (e) {
      e.preventDefault();
      const name = document.getElementById("contactName").value;
      const email = document.getElementById("contactEmail").value;
      const message = document.getElementById("contactMessage").value;

      try {
        const response = await fetch(`${BASE_API_URL}/contact`, {
          // Assuming /contact endpoint
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ name, email, message }),
        });

        const data = await response.json();

        if (response.ok) {
          showMessage("आपका संदेश सफलतापूर्वक भेज दिया गया है!", "success");
          closeModal("contactUsModal");
          document.getElementById("contactForm").reset();
        } else {
          showMessage(data.message || "संदेश भेजने में विफल।", "error");
        }
      } catch (error) {
        console.error("Contact form submission error:", error);
        showMessage("संदेश भेजते समय एक त्रुटि हुई।", "error");
      }
    });

  // Close modal when clicking outside content (for all modals)
  document.querySelectorAll(".modal-overlay").forEach((overlay) => {
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) {
        closeModal(overlay.id);
      }
    });
  });

  // --- Floating Particles Effect ---
  function createParticle() {
    const particle = document.createElement("div");
    particle.classList.add("particle");
    document.getElementById("particles").appendChild(particle);

    const size = Math.random() * 5 + 3; // 3-8px
    const x = Math.random() * window.innerWidth;
    const y = Math.random() * window.innerHeight;
    const duration = Math.random() * 10 + 5; // 5-15s
    const delay = Math.random() * 5; // 0-5s
    const opacity = Math.random() * 0.5 + 0.3; // 0.3-0.8

    particle.style.width = `${size}px`;
    particle.style.height = `${size}px`;
    particle.style.left = `${x}px`;
    particle.style.top = `${y}px`;
    particle.style.opacity = opacity;
    particle.style.animation = `float ${duration}s infinite ease-in-out ${delay}s`;

    // Remove particle after animation to prevent memory issues
    particle.addEventListener("animationend", () => {
      particle.remove();
    });
  }

  function animateParticles() {
    setInterval(createParticle, 500); // Create a new particle every 500ms
  }

  // --- Initial Calls ---
  checkAuthStatus(); // Check auth status on page load
  loadArticles(); // Load articles on page load
  animateParticles(); // Start particle animation
});