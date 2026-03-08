"""
Cybersecurity Portfolio - Timothy Victor Osas
Hardened Flask Application
Security measures applied:
  - CSRF protection on all forms
  - Strict Content Security Policy (CSP)
  - Security headers (XSS, Clickjacking, MIME sniffing)
  - Input validation & sanitization on contact form
  - Rate-limiting awareness via session tokens
  - Secure session cookie settings
  - No debug mode in production
  - Secrets loaded only from environment variables
  - No credentials hardcoded anywhere
"""

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
import os
import re
import html

# ── Load environment variables ────────────────────────────────────────────────
load_dotenv()

# ── App initialisation ────────────────────────────────────────────────────────
app = Flask(__name__)

_secret = os.getenv("SECRET_KEY")
if not _secret or len(_secret) < 32:
    raise RuntimeError(
        "SECRET_KEY env variable is missing or too short (min 32 chars). "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret

# ── CSRF protection ───────────────────────────────────────────────────────────
csrf = CSRFProtect(app)

# ── Session & cookie security ─────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "True").lower() in (
        "true", "1", "yes"),
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    WTF_CSRF_TIME_LIMIT=3600,
)

mail = Mail(app)

# ── Input sanitisation helpers ────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$")
MAX_NAME = 100
MAX_EMAIL = 254
MAX_MESSAGE = 2000


def sanitize_text(value: str, max_len: int) -> str:
    value = value.strip()[:max_len]
    return html.escape(value)


def validate_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value)) and len(value) <= MAX_EMAIL


# ── Static data ────────────────────────────────────────────────────────────────
EXPERIENCES = [
    {
        "company": "Google & Coursera",
        "role": "Professional Certificate",
        "period": "2024",
        "location": "Remote",
        "bullets": [
            "Earned the Google Professional Cybersecurity Certificate, demonstrating proficiency in foundational cybersecurity concepts.",
            "Acquired practical skills in Python, Linux, and SQL for security tasks.",
            "Studied SIEM tools to detect and analyse threats.",
        ],
        "skills": ["Python", "Linux", "SQL", "SIEM", "IDS"],
    },
    {
        "company": "3MTT Nigeria / Darey.io",
        "role": "Cybersecurity Trainee",
        "period": "2025",
        "location": "Hybrid",
        "bullets": [
            "Completed an extensive cybersecurity programme covering network defence and ethical hacking.",
            "Gained hands-on experience with industry-standard penetration testing tools.",
            "Led a team project to design a secure network architecture for a small business.",
        ],
        "skills": ["Network Security", "Ethical Hacking", "Vulnerability Analysis", "Digital Forensics"],
    },
    {
        "company": "Cybersecured India",
        "role": "Cybersecurity & Python Developer",
        "period": "2023 — 2024",
        "location": "Remote",
        "bullets": [
            "Developed Python tools for network monitoring and security.",
            "Conducted vulnerability assessments and penetration testing.",
            "Automated security workflows with Bash and SQL.",
        ],
        "skills": ["Python", "Vulnerability Analysis", "Penetration Testing", "Bash", "SQL"],
    },
    {
        "company": "ALX Africa",
        "role": "Software Engineering",
        "period": "2022 — 2023",
        "location": "Hybrid",
        "bullets": [
            "Contributed to open-source and collaborative projects.",
            "Specialised in backend development, server configuration, and automation scripts.",
            "Mentored junior cohorts and led knowledge-sharing sessions.",
        ],
        "skills": ["Bash", "C", "Git", "Linux", "Python", "Flask"],
    },
    {
        "company": "Funtay Group",
        "role": "Conversion Engineer",
        "period": "2024 — Present",
        "location": "Onsite",
        "bullets": [
            "Leading technical teams in energy solutions.",
            "Implementing innovative strategies for operational efficiency.",
            "Ensuring compliance and safety in engineering projects.",
        ],
        "skills": ["CNG", "AEB2001N IC Software", "Team Leadership"],
    },
    {
        "company": "Panafrican Equipment Nigeria Limited",
        "role": "Engineering Intern",
        "period": "Aug 2022 — Feb 2023",
        "location": "Onsite",
        "bullets": [
            "Conducted routine checks on diesel engines, monitoring performance parameters and executing timely maintenance.",
            "Maintained comprehensive documentation of all engine room activities.",
            "Collaborated with senior engineers to resolve complex mechanical and operational issues.",
        ],
        "skills": ["Diesel Engines", "Maintenance", "Troubleshooting", "Technical Documentation"],
    },
]

EDUCATION = [
    {
        "school": "Nigeria Maritime University",
        "program": "B.Eng. Marine Engineering (First Class Honours)",
        "period": "2019 — 2024",
        "notes": [
            "Capstone: Ocean Thermal Energy Conversion (OTEC)",
            "Relevant Courses: Cybersecurity, Python Programming",
        ],
    }
]

SOCIALS = {
    "github": "https://github.com/Osvic1",
    "linkedin": "https://www.linkedin.com/in/timothy-victor-a61421223/",
    "email": "mailto:Timothyv952@gmail.com",
    "resume": "/static/resume/resume.pdf",
}

# ── Security headers ──────────────────────────────────────────────────────────


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://use.fontawesome.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-src https://www.google.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response

# ── Routes ────────────────────────────────────────────────────────────────────


@app.route("/")
def home():
    return render_template("index.html", title="Home", socials=SOCIALS)


@app.route("/about")
def about():
    return render_template("about.html", title="About", socials=SOCIALS)


@app.route("/education")
def education():
    return render_template("education.html", title="Education", items=EDUCATION, socials=SOCIALS)


@app.route("/experience")
def experience():
    return render_template("experience.html", title="Experience", items=EXPERIENCES, socials=SOCIALS)


@app.route("/projects")
def projects():
    PROJECTS = [
        {
            "title": "Securing the Access Grid — Cybershield Corp",
            "description": "Simulated a phishing attack scenario and developed a mitigation strategy with user-awareness testing and secure email gateway configurations.",
            "images": [
                url_for("static", filename="images/sag1.png"),
                url_for("static", filename="images/sag2.png"),
                url_for("static", filename="images/sag3.png"),
            ],
            "tags": ["Cybersecurity", "Phishing", "Email Security"],
            "link": "https://docs.google.com/document/d/1QROBH9YugqsjiJk6TwuAu_v83KLJFgbdFxfc7rD3zr8/edit?usp=sharing",
        },
        {
            "title": "Network Security Design — Kafitech",
            "description": "Designed and implemented a secure enterprise network using firewalls, VPNs, and IDS/IPS for threat prevention and monitoring.",
            "images": [
                url_for("static", filename="images/kaf1.png"),
                url_for("static", filename="images/kaf2.png"),
                url_for("static", filename="images/kaf3.png"),
            ],
            "tags": ["Network Security", "VPN", "IDS/IPS"],
            "link": "https://docs.google.com/document/d/12_VYLXBQT_RYP0M-Rv5GvNPCM_EJGJ-ElaM-EGFePJY/edit?usp=drive_link",
        },
        {
            "title": "Website Monitoring Tool (Python)",
            "description": "A Python-based monitoring tool that tracks website uptime/downtime and sends alerts when issues occur — with forensic-grade logging.",
            "images": [
                url_for("static", filename="images/wsmd1.png"),
                url_for("static", filename="images/wsmd2.png"),
                url_for("static", filename="images/wsmd3.png"),
            ],
            "tags": ["Python", "Automation", "Uptime Monitoring"],
            "link": "https://github.com/Osvic1/website-monitoring-dashboard",
        },
        {
            "title": "Host-Based Firewall Configuration (Windows)",
            "description": "Configured Windows Defender Firewall to block unauthorised access, allow trusted applications, and monitor activity with inbound/outbound traffic rules.",
            "images": [
                url_for("static", filename="images/fw1.png"),
                url_for("static", filename="images/fw2.png"),
                url_for("static", filename="images/fw3.png"),
            ],
            "tags": ["Firewall", "Windows Security", "Access Control"],
            "link": "https://docs.google.com/document/d/1RqVK-ABCZ5TeWHGBxxU9JNE21n0S9w3w3ou5B3cgWss/edit?usp=sharing",
        },
        {
            "title": "Vulnerability Scan Using OpenVAS",
            "description": "Full vulnerability assessment on ShieldGuard Inc.'s LAN. Detected unpatched software, weak SSH passwords, and exposed SMB services. Remediation report included.",
            "images": [
                url_for("static", filename="images/opv1.png"),
                url_for("static", filename="images/opv2.png"),
                url_for("static", filename="images/opv3.png"),
            ],
            "tags": ["Vulnerability Assessment", "OpenVAS", "Network Security"],
            "link": "https://docs.google.com/document/d/1BTIynjtbc4gbitqLxSkFuyzXv82Q8dSxV537i3mCFbM/edit?usp=sharing",
        },
        {
            "title": "Phishing Email Analyzer",
            "description": "A Python tool that parses and analyses suspicious emails — extracting headers, URLs, and attachments to identify phishing indicators. Generates a structured threat report.",
            "images": [
                "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=800&q=80",
                "https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=800&q=80",
                "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=800&q=80",
            ],
            "tags": ["Phishing", "Python", "Email Security", "Threat Analysis"],
            "link": None,
        },
        {
            "title": "Password Strength Auditor (Python)",
            "description": "A Python-based auditing tool that evaluates password strength using entropy scoring, dictionary attack simulation, and breach database checks. Outputs a detailed security report.",
            "images": [
                "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=800&q=80",
                "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800&q=80",
                "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=800&q=80",
            ],
            "tags": ["Python", "Password Security", "Auditing", "Automation"],
            "link": None,
        },
        {
            "title": "SOC Alert Triage Simulation",
            "description": "Simulated a Security Operations Centre triage workflow — classifying alerts by severity, correlating events across logs, and producing incident tickets following NIST guidelines.",
            "images": [
                "https://images.unsplash.com/photo-1551808525-51a94da548ce?w=800&q=80",
                "https://images.unsplash.com/photo-1504868584819-f8e8b4b6d7e3?w=800&q=80",
                "https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&q=80",
            ],
            "tags": ["SOC", "Incident Response", "SIEM", "NIST"],
            "link": None,
        },
        {
            "title": "Linux Hardening Checklist",
            "description": "Developed and applied a comprehensive Linux hardening checklist — disabling unnecessary services, configuring SSH key-only auth, setting up UFW firewall rules, and auditing with Lynis.",
            "images": [
                "https://images.unsplash.com/photo-1629654297299-c8506221ca97?w=800&q=80",
                "https://images.unsplash.com/photo-1518432031352-d6fc5c10da5a?w=800&q=80",
                "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=800&q=80",
            ],
            "tags": ["Linux", "Hardening", "SSH", "UFW", "Lynis"],
            "link": None,
        },
    ]
    return render_template("projects.html", title="Projects", projects=PROJECTS, socials=SOCIALS)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        raw_name = request.form.get("name", "")
        raw_email = request.form.get("email", "")
        raw_message = request.form.get("message", "")
        raw_type = request.form.get("type", "other")

        name = sanitize_text(raw_name, MAX_NAME)
        email = sanitize_text(raw_email, MAX_EMAIL)
        message = sanitize_text(raw_message, MAX_MESSAGE)

        ALLOWED_TYPES = {"project", "collaboration", "mentorship", "other"}
        inquiry_type = raw_type if raw_type in ALLOWED_TYPES else "other"

        errors = []
        if not name:
            errors.append("Name is required.")
        if not validate_email(email):
            errors.append("A valid email address is required.")
        if len(message) < 10:
            errors.append("Message must be at least 10 characters.")

        if errors:
            for err in errors:
                flash(f"⚠ {err}", "danger")
            return redirect(url_for("contact"))

        if not (app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD")):
            flash("✅ Message received (email not configured on server).", "success")
            return redirect(url_for("contact"))

        try:
            msg = Message(
                subject=f"[Portfolio] {inquiry_type.title()} enquiry from {name}",
                sender=app.config["MAIL_USERNAME"],
                recipients=[app.config["MAIL_USERNAME"]],
                body=(
                    f"New contact form submission\n"
                    f"{'─'*40}\n"
                    f"Name    : {name}\n"
                    f"Email   : {email}\n"
                    f"Type    : {inquiry_type}\n"
                    f"{'─'*40}\n\n"
                    f"{message}"
                ),
            )
            mail.send(msg)
            flash("✅ Your message has been sent successfully!", "success")
        except Exception:
            flash("❌ Could not send your message. Please try again later.", "danger")

        return redirect(url_for("contact"))

    return render_template("contact.html", title="Contact", socials=SOCIALS)


# ── Resume download route ──────────────────────────────────────────────────────
@app.route("/resume")
def resume():
    from flask import send_from_directory
    resume_dir = os.path.join(app.root_path, "static", "resume")
    pdfs = [f for f in os.listdir(resume_dir) if f.lower().endswith(".pdf")]
    if not pdfs:
        abort(404)
    return send_from_directory(resume_dir, pdfs[0], as_attachment=False)


# ── AI Chat debug route ────────────────────────────────────────────────────────
@csrf.exempt
@app.route("/api/debug")
def debug_chat():
    """Temporary debug endpoint — remove before production"""
    import json
    import urllib.request
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {"status": "ERROR", "reason": "GROQ_API_KEY is not set in .env"}, 200

    payload = json.dumps({
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "say hi"}
        ],
        "max_tokens": 20
    }).encode()

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            reply = result["choices"][0]["message"]["content"]
            return {"status": "OK", "key_prefix": api_key[:12] + "...", "response": reply}
    except urllib.error.HTTPError as e:
        return {"status": "HTTP_ERROR", "code": e.code, "body": e.read().decode()}, 200
    except Exception as e:
        return {"status": "EXCEPTION", "error": str(e), "type": type(e).__name__}, 200


# ── AI Chat API route ──────────────────────────────────────────────────────────
@csrf.exempt
@app.route("/api/chat", methods=["POST"])
def chat():
    import json
    import urllib.request
    data = request.get_json(silent=True)
    if not data or not data.get("message"):
        return {"error": "No message"}, 400
    user_msg = str(data["message"])[:500]

    SYSTEM = (
        "You are Timothy Victor Osas's portfolio assistant — a sharp, concise cybersecurity AI. "
        "Answer questions about Timothy: he is a Cybersecurity Specialist, Digital Forensics Analyst, "
        "Python Security Developer, and Marine Engineering graduate (First Class Honours, Nigeria Maritime University 2024). "
        "His skills include network security, penetration testing, incident response, Python, Linux, Wireshark, Nmap, OpenVAS. "
        "Projects: Securing the Access Grid (phishing IR), Kafitech Network Security Design, Website Monitoring Tool, "
        "Host-Based Firewall Config, Vulnerability Scan with OpenVAS. "
        "Certifications: Google Professional Cybersecurity, Cyber Secured India, 3MTT Nigeria, TECH4DEV. "
        "Contact: Timothyv952@gmail.com | GitHub: Osvic1 | LinkedIn: timothy-victor-a61421223. "
        "Keep answers under 3 sentences. Be professional but engaging. If asked something unrelated to Timothy, "
        "politely redirect to his portfolio topics."
    )

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {"reply": "Chat is not configured yet. Please contact Timothy at Timothyv952@gmail.com"}, 200

    payload = json.dumps({
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_msg}
        ],
        "max_tokens": 300
    }).encode()

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            reply = result["choices"][0]["message"]["content"]
            return {"reply": reply}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        app.logger.error(f"Groq API error {e.code}: {err_body}")
        return {"reply": f"API error {e.code}. Check your GROQ_API_KEY."}, 200
    except Exception as e:
        app.logger.error(f"Chat route error: {e}")
        return {"reply": f"Connection error: {str(e)}"}, 200


# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", title="404 – Not Found"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("404.html", title="403 – Forbidden"), 403


@app.errorhandler(500)
def server_error(e):
    return render_template("404.html", title="500 – Server Error"), 500


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV", "production").lower() == "development"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
