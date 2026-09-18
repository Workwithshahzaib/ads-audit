"""
api/index.py — Google Ads Audit Tool web app (FastAPI).
Runs on Vercel as a serverless function, or locally with:  python api/index.py
"""

import os
import secrets
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Allow http://localhost during development (Google requires https in production)
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from google_auth_oauthlib.flow import Flow
from starlette.middleware.sessions import SessionMiddleware

import audit

BASE = Path(__file__).parent
PORT = int(os.getenv("PORT", "3000"))

# Where this app is reachable. On Vercel it is detected from the project domain;
# locally it falls back to http://localhost:3000. Override with BASE_URL.
if os.getenv("BASE_URL"):
    BASE_URL = os.environ["BASE_URL"].rstrip("/")
elif os.getenv("VERCEL_PROJECT_PRODUCTION_URL"):
    BASE_URL = "https://" + os.environ["VERCEL_PROJECT_PRODUCTION_URL"]
else:
    BASE_URL = f"http://localhost:{PORT}"
REDIRECT_URI = f"{BASE_URL}/auth/google/callback"
SCOPES = ["https://www.googleapis.com/auth/adwords"]

REQUIRED_ENV = ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SESSION_SECRET")
MISSING_ENV = [v for v in REQUIRED_ENV if not os.getenv(v)]

app = FastAPI(title="Google Ads Audit Tool")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET") or secrets.token_hex(32),
    max_age=60 * 60 * 24 * 30,
    same_site="lax",
    https_only=BASE_URL.startswith("https"),
)
templates = Jinja2Templates(directory=str(BASE / "templates"))


@app.middleware("http")
async def require_setup(request: Request, call_next):
    """Show a friendly setup page instead of crashing when env vars are missing."""
    if MISSING_ENV:
        return templates.TemplateResponse(
            request, "setup.html",
            {"missing": MISSING_ENV, "redirect_uri": REDIRECT_URI, "base_url": BASE_URL},
            status_code=503)
    return await call_next(request)


def _flow(state: str | None = None) -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
    )


ERROR_HINTS = [
    ("access_denied", "You clicked Cancel on the Google consent screen, or your Google account is not "
                      "added as a test user (Google Cloud → Google Auth Platform → Audience → Test users)."),
    ("CLOUD_PROJECT_NOT_APPROVED_FOR_PRODUCTION", "The Cloud project only has Test access. Wait for "
                                                  "Explorer access or apply for Basic in the Google Ads API Overview page."),
    ("ACTION_NOT_PERMITTED", "The Cloud project is not approved for production accounts yet."),
    ("RESOURCE_EXHAUSTED", "Daily API operation limit reached (Explorer = 2,880/day). Try tomorrow or apply "
                           "for Basic access."),
    ("USER_PERMISSION_DENIED", "This Google login does not have access to that Ads account, or the "
                               "login-customer-id (manager) is wrong. Try picking the account again."),
    ("CUSTOMER_NOT_FOUND", "Account ID not found under this login."),
    ("invalid_grant", "The saved Google login expired or was revoked. Log out and connect again."),
    ("DEVELOPER_TOKEN", "Developer tokens were retired in September 2026; make sure GOOGLE_DEVELOPER_TOKEN in "
                        ".env is any non-empty placeholder and that the Cloud project has the Google Ads API enabled."),
]


def _error(request: Request, title: str, exc: Exception | str, status: int = 500):
    msg = str(exc)
    hints = [h for key, h in ERROR_HINTS if key.lower() in msg.lower()]
    return templates.TemplateResponse(
        request, "error.html",
        {"title": title, "message": msg, "hints": hints}, status_code=status)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("refresh_token"):
        return RedirectResponse("/accounts")
    return templates.TemplateResponse(request, "index.html", {"redirect_uri": REDIRECT_URI})


@app.get("/auth/google")
def auth_start(request: Request):
    flow = _flow()
    url, state = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true")
    request.session["oauth_state"] = state
    return RedirectResponse(url)


@app.get("/auth/google/callback")
def auth_callback(request: Request):
    if request.query_params.get("error"):
        return _error(request, "Google sign-in failed", request.query_params["error"], 400)
    state = request.session.pop("oauth_state", None)
    try:
        flow = _flow(state)
        flow.fetch_token(authorization_response=str(request.url))
    except Exception as e:
        return _error(request, "Could not complete Google sign-in", e, 400)
    creds = flow.credentials
    if not creds.refresh_token:
        return _error(request, "No refresh token returned",
                      "Google did not return a refresh token. Go to https://myaccount.google.com/permissions, "
                      "remove 'Google Ads Audit Tool', then connect again.", 400)
    request.session["refresh_token"] = creds.refresh_token
    return RedirectResponse("/accounts")


@app.get("/accounts", response_class=HTMLResponse)
def accounts(request: Request):
    token = request.session.get("refresh_token")
    if not token:
        return RedirectResponse("/")
    try:
        accts, errors = audit.list_accessible_accounts(token)
    except Exception as e:
        return _error(request, "Could not list Google Ads accounts", e)
    return templates.TemplateResponse(request, "accounts.html",
                                      {"accounts": accts, "errors": errors})


@app.get("/audit/{customer_id}", response_class=HTMLResponse)
def run_audit(request: Request, customer_id: str, login: str | None = None):
    token = request.session.get("refresh_token")
    if not token:
        return RedirectResponse("/")
    try:
        result = audit.run_audit(token, customer_id, login)
    except Exception as e:
        return _error(request, "Audit failed", e)
    return templates.TemplateResponse(request, "report.html",
                                      {"r": result, "today": date.today().strftime("%d %b %Y")})


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


if __name__ == "__main__":
    print(f"\n  Google Ads Audit Tool running at {BASE_URL}\n  Press Ctrl+C to stop.\n")
    uvicorn.run(app, host="127.0.0.1", port=PORT)
