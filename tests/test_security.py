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


# ── Chat provider handling (Groq mocked) ─────────────────────────────────────

class _Resp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code, body):
    import io
    import urllib.error
    return urllib.error.HTTPError("https://api.groq.com", code, "err", {}, io.BytesIO(body))


def test_chat_success_and_key_is_cleaned(app, monkeypatch):
    import json
    import urllib.request
    app.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setenv("GROQ_API_KEY", '  "gsk_test_key"\n')
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["auth"] = req.get_header("Authorization")
        return _Resp(json.dumps({"choices": [{"message": {"content": "He builds AI platforms."}}]}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    r = https_client(app).post("/api/chat", json={"message": "hi"})
    assert r.status_code == 200 and r.get_json()["reply"] == "He builds AI platforms."
    assert seen["auth"] == "Bearer gsk_test_key"


def test_chat_falls_back_to_backup_model(app, monkeypatch):
    import json
    import urllib.request
    app.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key")
    models = []

    def fake_urlopen(req, timeout=0):
        model = json.loads(req.data)["model"]
        models.append(model)
        if len(models) == 1:
            raise _http_error(400, b'{"error":{"code":"model_decommissioned","message":"gone"}}')
        return _Resp(json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    r = https_client(app).post("/api/chat", json={"message": "hi"})
    assert r.status_code == 200
    assert models == ["openai/gpt-oss-120b", "llama-3.3-70b-versatile"]


def test_chat_bad_key_does_not_retry_or_leak(app, monkeypatch, caplog):
    import urllib.request
    app.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setenv("GROQ_API_KEY", "gsk_secret_value")
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        raise _http_error(401, b'{"error":{"code":"invalid_api_key","message":"Invalid API Key"}}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    r = https_client(app).post("/api/chat", json={"message": "hi"})
    assert r.status_code == 502 and len(calls) == 1
    assert "invalid_api_key" in caplog.text
    assert "gsk_secret_value" not in caplog.text and "gsk_secret_value" not in r.get_data(as_text=True)


def test_assistant_facts_match_site_data(app):
    with app.test_request_context("/api/chat"):
        text = portfolio.assistant_instructions()
    for job in portfolio.EXPERIENCES:
        assert job["company"] in text and job["period"] in text
    with app.test_request_context("/"):
        for p in portfolio.get_projects():
            assert "[" + p["title"] + "]" in text
    for c in portfolio.CERTIFICATIONS:
        assert c in text
    assert "Never move a technology" in text
    assert "victor-timothy-a61421223" in text


def test_reply_cleanup():
    raw = "**AtomStudio**—a fine‑tuning platform.\n- built with FastAPI"
    assert portfolio.clean_reply(raw) == "AtomStudio, a fine-tuning platform.\nbuilt with FastAPI"
