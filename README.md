# 🛡️ Timothy Victor Osas — Cybersecurity Portfolio

> A professional cybersecurity portfolio built with Flask, featuring a terminal/hacker aesthetic, full security hardening, and zero-sleep free hosting on Koyeb.

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square&logo=flask)
![Security](https://img.shields.io/badge/Security-Hardened-green?style=flat-square&logo=shield)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 🌐 Live Demo

**[Live Demo](https://timvictor.onrender.com/)**

---

## ✨ Features

- **Terminal / hacker aesthetic** — matrix rain background, CRT scanlines, monospace fonts
- **Fully responsive** — mobile, tablet, and desktop
- **Security hardened** — CSRF, CSP, HSTS, XSS protection, input sanitisation
- **Contact form** — CSRF-protected, server-side validated, Gmail SMTP
- **Project showcase** — auto-rotating image sliders
- **Animated stats** — intersection-observer-based counters
- **Typing role rotator** — cycles through cybersecurity titles
- **Zero-sleep hosting** — deployed on Koyeb (always-on free tier)

---

## 🗂️ Project Structure

```
cybersec_portfolio/
├── app.py                  # Main Flask application (security hardened)
├── requirements.txt        # Python dependencies
├── Procfile                # For Koyeb / Heroku deployment
├── wsgi.py                 # WSGI entry point for production
├── runtime.txt             # Python version specification
├── .env.example            # Environment variable template (safe to commit)
├── .gitignore              # Excludes .env and sensitive files
├── setup.bat               # Windows: one-click setup
├── run.bat                 # Windows: one-click run
├── static/
│   ├── images/             # Project screenshots
│   ├── docs/               # Certificates (PDF)
│   ├── resume/             # Resume PDF
│   └── js/main.js          # Scroll-to-top, smooth scroll
└── templates/
    ├── base.html           # Base layout (matrix, nav, footer)
    ├── index.html          # Home — hero, skills, featured project
    ├── about.html          # About — bio, skills cloud
    ├── education.html      # Education + certifications
    ├── experience.html     # Timeline of work experience
    ├── projects.html       # Project cards with image sliders
    ├── contact.html        # CSRF-protected contact form
    └── 404.html            # Custom error page
```

---

## 🔒 Security Measures

| Layer                   | Implementation                                              |
| ----------------------- | ----------------------------------------------------------- |
| CSRF Protection         | Flask-WTF token on every form POST                          |
| Content Security Policy | Tight CSP header — blocks inline scripts, restricts origins |
| XSS Protection          | `X-XSS-Protection`, HTML escaping on all user inputs        |
| Clickjacking            | `X-Frame-Options: DENY`                                     |
| MIME Sniffing           | `X-Content-Type-Options: nosniff`                           |
| HTTPS Enforcement       | `Strict-Transport-Security` (HSTS)                          |
| Input Validation        | Email regex, max lengths, whitelist for dropdown values     |
| Secret Key              | Enforced from environment — app refuses to start without it |
| Error Handling          | Generic user messages — no internal details leaked          |
| Debug Mode              | Tied to `FLASK_ENV=development` — off in production         |

---

## 🚀 Local Setup (Windows)

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/cybersec-portfolio.git
cd cybersec-portfolio

# 2. Run setup (creates venv + installs deps)
setup.bat

# 3. Copy and fill in environment variables
copy .env.example .env
# Edit .env with your SECRET_KEY and Gmail credentials

# 4. Start the server
run.bat

# 5. Open browser
# http://127.0.0.1:5000
```

**Or manually (any OS):**

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate.bat     # Windows

pip install -r requirements.txt
cp .env.example .env
# Edit .env

flask run
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```env
FLASK_ENV=development
SECRET_KEY=your_64_char_random_hex_here
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your.email@gmail.com
MAIL_PASSWORD=your_gmail_app_password
```

**Generating a secure SECRET_KEY:**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**Gmail App Password:**
Google Account → Security → 2-Step Verification → App Passwords → Generate

---

## ☁️ Deploying to Koyeb (Free, Never Sleeps)

1. Push this repo to GitHub
2. Go to [koyeb.com](https://koyeb.com) → Sign up free
3. New App → **GitHub** → Select your repo
4. Set **Build command:** `pip install -r requirements.txt`
5. Set **Run command:** `gunicorn wsgi:app`
6. Add environment variables (from your `.env`) in the Koyeb dashboard
7. Deploy — your app gets a permanent `*.koyeb.app` URL

See full guide: [DEPLOYMENT.md](DEPLOYMENT.md)

---

## 📄 License

MIT — feel free to fork and customise for your own portfolio.

---

_Built with Flask · Secured with love · Hosted on Render_
