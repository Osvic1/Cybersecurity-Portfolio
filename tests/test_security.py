import re

import pytest

import app as portfolio
from conftest import https_client

PAGES = ["/", "/about", "/education", "/experience", "/projects", "/contact"]


def csp_of(resp):
    return dict(
        (part.split(" ", 1)[0], part.split(" ", 1)[1] if " " in part else "")
        for part in (p.strip() for p in resp.headers["Content-Security-Policy"].split(";"))
        if part
    )


# ── Pages and routes ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", PAGES)
def test_pages_load(client, path):
    assert client.get(path).status_code == 200


def test_unknown_page_is_404(client):
    assert client.get("/does-not-exist").status_code == 404


def test_debug_endpoint_removed(client):
    assert client.get("/api/debug").status_code == 404


def test_resume_is_pdf(client):
    r = client.get("/resume")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"


def test_no_open_redirect(client):
    # Send the raw path; the test client would otherwise read "//host" as a hostname.
    r = client.get("/", environ_overrides={"PATH_INFO": "//evil.example.com"})
    assert r.status_code == 404
    assert "Location" not in r.headers


def test_security_txt(client):
    r = client.get("/.well-known/security.txt")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Contact: mailto:" in body and "Expires: " in body


# ── Security headers (OWASP Secure Headers Project) ──────────────────────────

@pytest.mark.parametrize("path", PAGES)
def test_security_headers(client, path):
    h = client.get(path).headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-XSS-Protection"] == "0"
    assert "max-age=31536000" in h["Strict-Transport-Security"]
    assert h["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert h["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "camera=()" in h["Permissions-Policy"]


@pytest.mark.parametrize("path", PAGES)
def test_csp_is_strict(client, path):
    csp = csp_of(client.get(path))
    assert "'unsafe-inline'" not in csp["script-src"]
    assert "'unsafe-eval'" not in csp["script-src"]
    assert "http:" not in csp["script-src"] and "https:" not in csp["script-src"].replace("'self'", "")
    assert csp["frame-ancestors"] == "'none'"
    assert csp["object-src"] == "'none'"
    assert csp["base-uri"] == "'self'"
    assert csp["form-action"] == "'self'"


@pytest.mark.parametrize("path", PAGES)
def test_every_inline_script_carries_the_nonce(client, path):
    r = client.get(path)
    nonce = re.search(r"'nonce-([^']+)'", r.headers["Content-Security-Policy"]).group(1)
    html = r.get_data(as_text=True)
    for tag in re.findall(r"<script\b[^>]*>", html):
        if "src=" in tag:
            assert re.search(r'src="/static/', tag), f"external script: {tag}"
        else:
            assert f'nonce="{nonce}"' in tag, f"inline script without nonce: {tag}"


def test_nonce_changes_per_request(client):
    a = client.get("/").headers["Content-Security-Policy"]
    b = client.get("/").headers["Content-Security-Policy"]
    assert re.search(r"nonce-[^']+", a).group() != re.search(r"nonce-[^']+", b).group()


@pytest.mark.parametrize("path", PAGES)
def test_no_inline_event_handlers(client, path):
    html = client.get(path).get_data(as_text=True)
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", html)


@pytest.mark.parametrize("path", PAGES)
def test_new_tab_links_are_isolated(client, path):
    html = client.get(path).get_data(as_text=True)
    for tag in re.findall(r"<a\b[^>]*target=\"_blank\"[^>]*>", html):
        assert "noopener" in tag, tag


def test_session_cookie_flags(client):
    client.get("/contact")
    cookie = client.get_cookie("__Host-session")
    assert cookie is not None
    assert cookie.secure and cookie.http_only
    assert cookie.same_site == "Strict"


# ── Contact form ─────────────────────────────────────────────────────────────

def test_contact_rejects_missing_csrf(client, monkeypatch):
    sent = []
    monkeypatch.setattr(portfolio.mail, "send", lambda m: sent.append(m))
    r = client.post("/contact", data={"name": "A", "email": "a@example.com", "message": "hello there friend"})
    assert r.status_code == 302
    assert not sent


def test_contact_strips_header_injection(app, monkeypatch):
    app.config["WTF_CSRF_ENABLED"] = False
    app.config.update(MAIL_USERNAME="me@example.com", MAIL_PASSWORD="x")
    sent = []
    monkeypatch.setattr(portfolio.mail, "send", lambda m: sent.append(m))
    try:
        c = https_client(app)
        c.post("/contact", data={
            "name": "Eve\r\nBcc: victim@example.com",
            "email": "eve@example.com",
            "message": "this is a long enough message",
        })
    finally:
        app.config.update(MAIL_USERNAME="", MAIL_PASSWORD="")
    assert len(sent) == 1
    assert "\n" not in sent[0].subject and "\r" not in sent[0].subject


def test_contact_rate_limit(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    data = {"name": "A", "email": "a@example.com", "message": "hello there friend"}
    for _ in range(5):
        c.post("/contact", data=data)
    r = c.post("/contact", data=data, follow_redirects=True)
    assert "Too many messages" in r.get_data(as_text=True)


def test_request_size_limit(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    r = c.post("/contact", data={"message": "x" * (64 * 1024)})
    assert r.status_code == 413


# ── Chat API ─────────────────────────────────────────────────────────────────

def test_chat_requires_csrf(client):
    r = client.post("/api/chat", json={"message": "hi"})
    assert r.status_code == 400


def test_chat_requires_json(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    assert c.post("/api/chat", data="message=hi").status_code == 415


def test_chat_rejects_bad_payloads(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    for body in ({}, {"message": ""}, {"message": 123}, ["x"]):
        assert c.post("/api/chat", json=body).status_code == 400


def test_chat_hides_internal_errors(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    r = c.post("/api/chat", json={"message": "hi"})
    text = r.get_data(as_text=True)
    assert "GROQ" not in text and "Traceback" not in text and "Error" not in text


def test_chat_rate_limit(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    codes = [c.post("/api/chat", json={"message": "hi"}).status_code for _ in range(13)]
    assert codes[-1] == 429


def test_chat_responses_not_cached(app):
    app.config["WTF_CSRF_ENABLED"] = False
    c = https_client(app)
    assert c.post("/api/chat", json={"message": "hi"}).headers["Cache-Control"] == "no-store"


# ── Helpers ──────────────────────────────────────────────────────────────────

def test_sanitize_text():
    assert portfolio.sanitize_text("<b>hi</b>", 100) == "&lt;b&gt;hi&lt;/b&gt;"
    assert portfolio.sanitize_text("a\r\nb", 100, single_line=True) == "a b"
    assert portfolio.sanitize_text("a\x00b\x07c", 100) == "abc"
    assert len(portfolio.sanitize_text("x" * 500, 100)) == 100
