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

from flask import Flask, render_template, request, redirect, url_for, flash, abort, g
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from collections import defaultdict, deque
import os
import re
import html
import time
import secrets
import datetime
import threading

# ── Load environment variables ────────────────────────────────────────────────
load_dotenv()

# ── App initialisation ────────────────────────────────────────────────────────
app = Flask(__name__)

# Behind the hosting provider's proxy, take the client address and scheme from
# the single hop it adds. Set TRUST_PROXY=0 when running without a proxy.
if os.getenv("TRUST_PROXY", "1") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

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
    SESSION_COOKIE_NAME="__Host-session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=32 * 1024,
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


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
LINE_BREAKS = re.compile(r"[\r\n]+")


def sanitize_text(value: str, max_len: int, single_line: bool = False) -> str:
    value = CONTROL_CHARS.sub("", value)
    if single_line:
        value = LINE_BREAKS.sub(" ", value)
    value = value.strip()[:max_len]
    return html.escape(value)


# ── Rate limiting ─────────────────────────────────────────────────────────────
# Small in-memory sliding window per client and action. Enough for a single
# instance; swap for Redis if the site ever runs on several.
_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def rate_limited(action: str, limit: int, window: int) -> bool:
    key = (action, request.remote_addr or "unknown")
    now = time.monotonic()
    with _hits_lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


def validate_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value)) and len(value) <= MAX_EMAIL


# ── Static data ────────────────────────────────────────────────────────────────
EXPERIENCES = [
    {
        "company": "CrowtherLabs-THCO",
        "url": "https://www.thcohq.com/",
        "role": "Security Engineer · AI Research (LLMs) · AI Full-Stack Engineer",
        "period": "Jun 2026 — Present",
        "location": "Lagos, Nigeria · Hybrid · Full-time",
        "bullets": [
            "Develop and deploy an internal CRM and delivery platform (React, FastAPI, MongoDB, Azure, GitHub Actions).",
            "Designed and built AtomStudio, a hosted LLM fine-tuning platform on rented GPUs (Unsloth, Vast.ai, Docker).",
            "Led several authorised penetration tests to the OWASP API Security Top 10 and PTES, delivering reports, findings trackers and remediation plans.",
        ],
        "skills": ["Python", "FastAPI", "React", "Azure", "Docker", "API Security", "OWASP"],
    },
    {
        "company": "Funtay Group",
        "role": "Conversion Engineer (CNG Systems)",
        "period": "Sep 2024 — May 2026",
        "location": "On-site",
        "bullets": [
            "Configured and calibrated CNG injection ECUs with AEB2001N interface software for each vehicle conversion.",
            "Diagnosed and resolved faults in conversion systems using software diagnostics and live sensor data.",
            "Led a team of technicians on vehicle conversions, setting procedures and checking quality before handover.",
            "Ran safety and compliance checks and kept technical records for every conversion.",
        ],
        "skills": ["ECU Calibration", "AEB2001N", "Diagnostics", "CNG Systems", "Team Leadership"],
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
]

EDUCATION = [
    {
        "school": "Nigeria Maritime University",
        "program": "B.Eng. Marine Engineering (First Class Honours)",
        "period": "2019 — 2024",
        "notes": [
            "Project: Ocean Thermal Energy Conversion (OTEC)",
            "Relevant Courses: Cybersecurity, Python Programming",
        ],
    }
]

SOCIALS = {
    "github": "https://github.com/Osvic1",
    "linkedin": "https://www.linkedin.com/in/victor-timothy-a61421223/",
    "email": "mailto:Timothyv952@gmail.com",
    "resume": "/static/resume/resume.pdf",
}

# ── Security headers ──────────────────────────────────────────────────────────


@app.before_request
def make_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(18)


@app.context_processor
def inject_csp_nonce():
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


@app.after_request
def set_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    csp = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        # Inline style attributes are used for layout tweaks; scripts stay nonce-only.
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https://images.unsplash.com",
        "connect-src 'self'",
        "media-src 'self'",
        "frame-src 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
    if request.is_secure:
        csp.append("upgrade-insecure-requests")
    response.headers["Content-Security-Policy"] = "; ".join(csp)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Legacy XSS auditor is off per OWASP guidance; CSP does this job now.
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=(), interest-cohort=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.path.startswith("/api/") or request.method == "POST":
        response.headers["Cache-Control"] = "no-store"
    return response

# ── Routes ────────────────────────────────────────────────────────────────────


@app.context_processor
def inject_globals():
    return {"current_year": datetime.date.today().year}


@app.route("/")
def home():
    featured = [p for p in get_projects() if p.get("featured")]
    chat_enabled = bool(os.environ.get("GROQ_API_KEY"))
    return render_template("index.html", title="Home", socials=SOCIALS, featured=featured, chat_enabled=chat_enabled)


@app.route("/about")
def about():
    return render_template("about.html", title="About", socials=SOCIALS)


@app.route("/education")
def education():
    return render_template("education.html", title="Education", items=EDUCATION, socials=SOCIALS)


@app.route("/experience")
def experience():
    return render_template("experience.html", title="Experience", items=EXPERIENCES, socials=SOCIALS)


def get_projects():
    """Project cards, newest and most significant first. Needs a request context (url_for)."""
    projects = [
        {
            "title": "CRM & Delivery Platform",
            "category": "Software Engineering",
            "group": "build",
            "featured": True,
            "summary": "One system for client relationships, delivery, recruitment and HR, in production on Azure.",
            "metric": ["140+", "commits shipped to production"],
            "role": "Full-stack engineer · Jun 2026 to present",
            "description": "Internal platform at CrowtherLabs-THCO that brings client relationships, the project delivery pipeline, task boards, recruitment and HR into one system instead of spreadsheets, message threads and separate tools.",
            "highlights": [
                "Built the recruitment workflow: CV parsing (PDF, DOCX, OCR), AI-assisted candidate sourcing and enrichment, and automatic de-duplication.",
                "Extended project delivery with stage ownership, team assignment and approval gates, plus an HR suite (leave, notice board, appraisals).",
                "Hardened it for production: server-side role-based authorisation, secrets removed from the repository, and index-backed queries for speed.",
                "Ships as a single container to Azure Container Apps through GitHub Actions CI/CD.",
            ],
            "images": [
                url_for("static", filename="images/projects/crm1.png"),
                url_for("static", filename="images/projects/crm2.png"),
                url_for("static", filename="images/projects/crm3.png"),
                url_for("static", filename="images/projects/crm4.png"),
            ],
            "tags": ["React", "FastAPI", "MongoDB / Cosmos DB", "Azure", "GitHub Actions", "Tailwind CSS"],
            "link": None,
            "note": "Private codebase",
        },
        {
            "title": "AtomStudio, LLM Fine-Tuning Platform",
            "category": "Software Engineering · AI",
            "group": "build",
            "featured": True,
            "summary": "Hosted LLM fine-tuning on GPUs rented by the minute, with live telemetry and side-by-side evaluation.",
            "metric": ["269", "commits, sole developer"],
            "role": "Sole developer · architecture, backend and deployment",
            "description": "Hosted platform for fine-tuning open-weight language models. A team uploads its own examples, sees a price before starting, and trains on GPUs rented by the minute, with a live view of the run, a side-by-side comparison of base and fine-tuned models, and checksummed model delivery.",
            "highlights": [
                "Designed a FastAPI control plane, GPU provisioner and training worker around typed job and event contracts.",
                "Automated GPU rental on Vast.ai within price ceilings, sized disks from model files, and released idle machines within seconds to control cost.",
                "LoRA / QLoRA and full fine-tunes with Unsloth; live loss and GPU telemetry with plain-language failure diagnosis.",
                "Workspace isolation, accounts and API keys, spend limits, an MCP server for AI agents, and an OWASP Top 10 review of the platform itself.",
            ],
            "images": [
                url_for("static", filename="images/projects/atom1.png"),
                url_for("static", filename="images/projects/atom2.png"),
                url_for("static", filename="images/projects/atom3.png"),
            ],
            "tags": ["Python", "FastAPI", "React", "Unsloth", "Vast.ai", "Docker", "MCP"],
            "link": None,
            "note": "Private codebase",
        },
        {
            "title": "HR & Payroll SaaS: API Security Assessment",
            "category": "Security Assessment · client anonymised",
            "group": "security",
            "featured": True,
            "summary": "OWASP API Top 10 assessment of a multi-tenant HR, payroll and wallet platform.",
            "metric": ["40", "findings · 1,001 test cases"],
            "role": "Black-box API assessment · September 2026",
            "description": "Authorised penetration test of the API behind a multi-tenant HR, payroll and employee-wallet platform, run against the OWASP API Security Top 10 (2023) with CVSS v3.1 scoring.",
            "scope": ["292 API routes", "51 modules", "1,001 test cases"],
            "severity": [
                {"label": "Critical", "count": 11, "level": "critical"},
                {"label": "High", "count": 5, "level": "high"},
                {"label": "Medium", "count": 16, "level": "medium"},
                {"label": "Low", "count": 8, "level": "low"},
            ],
            "highlights": [
                "Found an authentication weakness that could expose employee personal, salary and wallet data, and traced it as the root cause of 20 of the 40 findings, so one fix closes half the report.",
                "Flagged missing limits on financial operations and input-validation gaps affecting stability.",
                "Confirmed the controls that already worked (payroll approvals, double-spend protection, injection resistance) so engineering could focus effort.",
                "Delivered the final report, a findings tracker and a prioritised remediation plan, with a post-fix retest recommended.",
            ],
            "images": [],
            "tags": ["OWASP API Top 10", "Postman", "CVSS v3.1", "Authorisation Testing", "Tenant Isolation"],
            "link": None,
            "note": "Report under NDA",
        },
        {
            "title": "Fintech & KYC Platform: API Security Assessment",
            "category": "Security Assessment · client anonymised",
            "group": "security",
            "featured": True,
            "summary": "OWASP API Top 10 assessment of a fintech platform with KYC and payment flows.",
            "metric": ["14", "findings · 496 operations"],
            "role": "Black-box API assessment (staging) · September 2026",
            "description": "Authorised penetration test of a fintech platform's staging API, covering accounts, administration, identity verification (KYC) and payment flows, following the OWASP API Security Top 10 (2023) and PTES.",
            "scope": ["496 API operations", "20 test runs"],
            "severity": [
                {"label": "High", "count": 6, "level": "high"},
                {"label": "Medium", "count": 4, "level": "medium"},
                {"label": "Low", "count": 1, "level": "low"},
                {"label": "Info", "count": 3, "level": "info"},
            ],
            "highlights": [
                "Identified credential-exposure, administrative-control and KYC-integrity weaknesses to fix before the platform handles real users' data.",
                "Worked alongside engineering during the engagement; two findings were remediated or closed and verified by retest.",
                "Confirmed strong baseline controls: security headers, CORS, encrypted tokens, and resistance to injection and object-level access attacks.",
                "Delivered the final report, a findings tracker and an engineering remediation brief.",
            ],
            "images": [],
            "tags": ["OWASP API Top 10", "PTES", "OWASP WSTG", "CVSS v3.1", "Access Control"],
            "link": None,
            "note": "Report under NDA",
        },
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
    for p in projects:
        p.setdefault("group", "lab")
        p.setdefault("featured", False)
        p["slug"] = re.sub(r"[^a-z0-9]+", "-", p["title"].lower()).strip("-")
    return projects


@app.route("/projects")
def projects():
    return render_template("projects.html", title="Projects", projects=get_projects(), socials=SOCIALS)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        if rate_limited("contact", limit=5, window=600):
            flash("Too many messages in a short time. Please try again later or email me directly.", "danger")
            return redirect(url_for("contact"))

        raw_name = request.form.get("name", "")
        raw_email = request.form.get("email", "")
        raw_message = request.form.get("message", "")
        raw_type = request.form.get("type", "other")

        # Name and email end up in mail headers, so they must stay on one line.
        name = sanitize_text(raw_name, MAX_NAME, single_line=True)
        email = sanitize_text(raw_email, MAX_EMAIL, single_line=True)
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
                flash(err, "danger")
            return redirect(url_for("contact"))

        if not (app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD")):
            flash("The contact form is offline right now. Please email Timothyv952@gmail.com directly.", "danger")
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
            flash("Thanks, your message has been sent. I'll reply soon.", "success")
        except Exception:
            app.logger.exception("Contact form email failed")
            flash("Your message could not be sent. Please try again later or email me directly.", "danger")

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


# ── Chat API route ─────────────────────────────────────────────────────────────
# CSRF protected: the page sends the token in the X-CSRFToken header.
CHAT_FALLBACK = "Sorry, I can't answer right now. Please email Timothyv952@gmail.com."


@app.route("/api/chat", methods=["POST"])
def chat():
    import json
    import urllib.request
    if not request.is_json:
        return {"error": "Expected JSON"}, 415
    if rate_limited("chat", limit=12, window=60) or rate_limited("chat-day", limit=150, window=86400):
        return {"reply": "You've asked a lot of questions in a short time. Please try again later."}, 429
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("message"), str) or not data["message"].strip():
        return {"error": "No message"}, 400
    user_msg = sanitize_text(data["message"], 500)

    SYSTEM = (
        "You are Timothy Victor Osas's portfolio assistant — sharp, concise and professional. "
        "Answer questions about Timothy: he is a Security Engineer, AI researcher (LLMs) and AI full-stack engineer, "
        "and a Marine Engineering graduate (First Class Honours, Nigeria Maritime University 2024). "
        "Current role (Jun 2026 — present) at CrowtherLabs-THCO: he built AtomStudio, a hosted LLM fine-tuning platform "
        "(FastAPI, React, Unsloth LoRA/QLoRA, GPUs rented on Vast.ai, Docker, MCP server) as sole developer; develops and "
        "deploys an internal CRM and delivery platform (React, FastAPI, MongoDB/Cosmos DB, Azure Container Apps, GitHub Actions); "
        "and has led several authorised penetration tests to OWASP standards; two recent API examples are an HR & payroll SaaS "
        "(40 findings over 1,001 test cases) and a fintech/KYC platform (14 findings over 496 operations). "
        "Security clients are confidential: never name them or describe vulnerabilities beyond severity counts and business impact. "
        "Skills: API security testing, OWASP, CVSS, Postman, Burp Suite, Nmap, Python, FastAPI, React, Docker, Azure, LLM fine-tuning. "
        "Earlier projects: Securing the Access Grid (phishing IR), Kafitech Network Security Design, Website Monitoring Tool, "
        "Host-Based Firewall Config, Vulnerability Scan with OpenVAS. "
        "Certifications: Google Professional Cybersecurity, Cyber Secured India, 3MTT Nigeria, TECH4DEV. "
        "Contact: Timothyv952@gmail.com | GitHub: Osvic1 | LinkedIn: victor-timothy-a61421223. "
        "Keep answers under 3 sentences. Be professional but engaging. If asked something unrelated to Timothy, "
        "politely redirect to his portfolio topics."
    )

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {"reply": CHAT_FALLBACK}, 503

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
        app.logger.error("Chat provider returned HTTP %s", e.code)
        return {"reply": CHAT_FALLBACK}, 502
    except Exception:
        app.logger.exception("Chat request failed")
        return {"reply": CHAT_FALLBACK}, 502


# ── security.txt (RFC 9116) ────────────────────────────────────────────────────
@app.route("/.well-known/security.txt")
def security_txt():
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180)).strftime("%Y-%m-%dT00:00:00Z")
    body = (
        "Contact: mailto:Timothyv952@gmail.com\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
        f"Canonical: {request.url_root.rstrip('/')}/.well-known/security.txt\n"
    )
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


# ── Error handlers ─────────────────────────────────────────────────────────────
from flask_wtf.csrf import CSRFError  # noqa: E402


@app.errorhandler(CSRFError)
def csrf_error(e):
    if request.path.startswith("/api/"):
        return {"error": "Session expired. Refresh the page and try again."}, 400
    flash("Your session expired. Please refresh the page and try again.", "danger")
    return redirect(url_for("contact"))


@app.errorhandler(413)
def too_large(e):
    if request.path.startswith("/api/"):
        return {"error": "Request too large"}, 413
    return render_template("404.html", title="413 – Request Too Large"), 413


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
