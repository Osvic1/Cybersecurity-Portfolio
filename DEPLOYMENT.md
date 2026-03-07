# ☁️ Deploying to Koyeb — Free, Always-On Hosting

Koyeb is the best free Flask host in 2025:
- ✅ **Never sleeps** (unlike Render free tier)
- ✅ Free forever tier — no credit card needed
- ✅ Automatic HTTPS
- ✅ GitHub auto-deploy on every push
- ✅ Custom domains supported

---

## Step 1 — Push to GitHub

```bash
# Inside your cybersec_portfolio folder:
git init
git add .
git commit -m "Initial commit — cybersecurity portfolio"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cybersec-portfolio.git
git push -u origin main
```

> ⚠️ Make sure `.env` is NOT committed — it's in `.gitignore` already.

---

## Step 2 — Sign up on Koyeb

Go to 👉 **[https://app.koyeb.com](https://app.koyeb.com)**

- Click **Sign up** → use GitHub (easiest)
- No credit card required

---

## Step 3 — Create a New App

1. Click **"Create App"**
2. Choose **"GitHub"** as the source
3. Select your `cybersec-portfolio` repository
4. Select branch: `main`

---

## Step 4 — Configure Build & Run

| Setting | Value |
|---|---|
| **Builder** | Buildpack |
| **Build command** | `pip install -r requirements.txt` |
| **Run command** | `gunicorn wsgi:app` |
| **Port** | `8000` |

---

## Step 5 — Add Environment Variables

Click **"Advanced"** → **"Environment Variables"** and add:

| Key | Value |
|---|---|
| `SECRET_KEY` | your 64-char random hex |
| `FLASK_ENV` | `production` |
| `MAIL_USERNAME` | your Gmail address |
| `MAIL_PASSWORD` | your Gmail App Password |
| `MAIL_SERVER` | `smtp.gmail.com` |
| `MAIL_PORT` | `587` |
| `MAIL_USE_TLS` | `True` |

**Generate SECRET_KEY:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Step 6 — Deploy!

Click **"Deploy"** — Koyeb will:
1. Pull your code from GitHub
2. Install dependencies
3. Start gunicorn
4. Assign you a URL like `https://your-app-name.koyeb.app`

Takes about 2–3 minutes on first deploy.

---

## Step 7 — Auto-Deploy on Push

Every time you `git push`, Koyeb automatically redeploys. No manual action needed.

---

## Troubleshooting

**App won't start?**
- Check Koyeb logs in the dashboard
- Make sure all env vars are set
- Make sure `gunicorn` is in `requirements.txt`

**Contact form not sending?**
- Use a Gmail **App Password**, not your main password
- Enable 2-Step Verification first on your Google account

**Custom domain?**
- Koyeb → App → Settings → Domains → Add your domain
- Update your DNS CNAME to point to Koyeb

---

## Other Free Hosting Options (Comparison)

| Platform | Free Tier | Sleeps? | Notes |
|---|---|---|---|
| **Koyeb** ✅ | Always free | ❌ Never | Best for Flask, recommended |
| Railway | $5 credit/month | ❌ Never | Runs out, then paid |
| Render | Free | ✅ After 15min | Slow cold start |
| PythonAnywhere | Free | ❌ Never | Good but limited traffic |
| Fly.io | Free allowance | ❌ Never | Needs credit card |

**Koyeb is the winner for your use case.**
