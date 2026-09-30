import os
import sys

import pytest

os.environ.setdefault("SECRET_KEY", "test-" + "x" * 40)
os.environ["GROQ_API_KEY"] = ""
os.environ["MAIL_USERNAME"] = ""
os.environ["MAIL_PASSWORD"] = ""
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as portfolio  # noqa: E402


@pytest.fixture
def app():
    portfolio.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    portfolio._hits.clear()
    yield portfolio.app
    portfolio.app.config.update(WTF_CSRF_ENABLED=True)
    portfolio._hits.clear()


def https_client(flask_app):
    # HTTPS so the Secure, __Host- prefixed session cookie is kept between requests.
    c = flask_app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    return c


@pytest.fixture
def client(app):
    return https_client(app)
