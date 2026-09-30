# Timothy Victor Osas: Portfolio

Personal portfolio of Timothy Victor Osas, security engineer, AI researcher (LLMs) and AI full-stack engineer.
Built with Flask and hardened against the OWASP Top 10 and the OWASP Secure Headers guidance.

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**Live site:** https://timvictor.onrender.com/

---

## Features

- Editorial dark design with a light theme toggle, responsive from 320 px phones to wide desktops
- Case studies for engineering, AI and security work, with anonymised severity summaries for client assessments
- First-visit intro sequence (skippable, keyboard accessible, respects reduced-motion settings)
- CSRF-protected contact form with server-side validation and rate limiting
- Optional assistant on the home page, shown only when a `GROQ_API_KEY` is configured
- No third-party scripts: icons are inline SVG and all JavaScript is served from the site itself

## Project structure

```
app.py                  Flask app: routes, data, security headers, rate limiting
wsgi.py                 WSGI entry point for production
requirements.txt        Runtime dependencies
requirements-dev.txt    Test and audit tools
tests/                  Security and route tests (pytest)
static/
  css/site.css          Design system (dark and light themes)
  js/main.js            Theme, navigation, reveal and carousel behaviour
  js/intro.js           First-visit intro sequence
  images/projects/      Project screenshots (demo data only)
  resume/resume.pdf     CV
templates/
  base.html             Layout, navigation, footer
  _icons.html           Inline SVG icon set
  _work.html            Shared project card macros
  _intro.html           Intro sequence markup
  index.html, projects.html, experience.html, about.html,
  education.html, contact.html, 404.html
```

## Security

| Area | Implementation |
| --- | --- |
| Content Security Policy | Per-request nonce for scripts, no `unsafe-inline` or `unsafe-eval` for scripts, no third-party script hosts, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri` and `form-action` locked to self |
| Response headers | HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `X-XSS-Protection: 0` as OWASP recommends |
| CSRF | Flask-WTF tokens on the contact form and on the chat API (sent as `X-CSRFToken`) |
| Sessions | `__Host-` prefixed cookie, `Secure`, `HttpOnly`, `SameSite=Strict` |
| Input handling | Control characters stripped, single-line fields cannot inject mail headers, HTML escaped, length limits, allow-listed options, 32 KB request limit |
| Abuse protection | Per-IP rate limits on the contact form and chat API |
| Error handling | Generic messages to visitors, details only in server logs, no debug endpoints |
| Secrets | Loaded from environment only; the app refuses to start without a strong `SECRET_KEY` |
| Disclosure | `/.well-known/security.txt` (RFC 9116) |
| Dependencies | Checked with `pip-audit` |

## Running locally

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
cp .env.example .env            # then fill in the values below
python app.py                   # http://127.0.0.1:5000
```

Environment variables:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Required, at least 32 characters: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `MAIL_USERNAME`, `MAIL_PASSWORD` | Gmail address and app password for the contact form |
| `GROQ_API_KEY` | Optional, enables the home page assistant |
| `TRUST_PROXY` | `1` (default) behind a hosting proxy such as Render, `0` when serving directly |
| `FLASK_ENV` | `development` enables debug mode locally; leave unset in production |

Session cookies are marked `Secure`, so the contact form and assistant need HTTPS. Browse the deployed site to test them end to end.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q        # routes, headers, CSP nonces, CSRF, rate limits, input handling
python -m pip_audit -r requirements.txt
```

## License

MIT
