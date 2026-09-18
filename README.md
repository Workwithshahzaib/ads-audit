# Google Ads Audit Tool — web app

One-click, read-only Google Ads audit. Users sign in with Google, pick an account,
and get a scored report with 12 checks and fix instructions. Runs on Vercel.

## Deploy in 3 steps (no coding)

### Step 1 — Put the code on GitHub
1. Go to https://github.com/new → Repository name: `ads-audit` → **Private** → *Create repository*.
2. On the new repo page click **uploading an existing file**.
3. Unzip this download, then drag **everything inside** the `ads-audit-vercel` folder
   (the `api` folder, `vercel.json`, `requirements.txt`, `README.md`, `.gitignore`,
   `.env.example`) into the upload box. Click **Commit changes**.
   - Check the repo shows `api/index.py` and `vercel.json` at the top level.

### Step 2 — Deploy on Vercel
1. Go to https://vercel.com/new → **Import** the `ads-audit` repository.
2. Leave Framework Preset as *Other*. Open **Environment Variables** and add:

   | Name | Value |
   |---|---|
   | `GOOGLE_CLIENT_ID` | your Client ID (ends with `.apps.googleusercontent.com`) |
   | `GOOGLE_CLIENT_SECRET` | your Client Secret (starts with `GOCSPX-`) |
   | `SESSION_SECRET` | any long random text, e.g. mash the keyboard for 40 characters |
   | `GOOGLE_DEVELOPER_TOKEN` | `NOT_NEEDED_SINCE_SEPT_2026` |

3. Click **Deploy**. Wait for the confetti. Note your app URL, e.g. `https://ads-audit-xxxx.vercel.app`.
   (Vercel → project → Settings → Domains shows it.)

### Step 3 — Tell Google the new address
1. Google Cloud Console → **APIs & Services → Credentials** → click **Audit Tool Web**.
2. Under *Authorized JavaScript origins* click **Add URI** → `https://YOUR-APP.vercel.app`
3. Under *Authorized redirect URIs* click **Add URI** → `https://YOUR-APP.vercel.app/auth/google/callback`
4. **Save**. Wait 1–2 minutes.

Open your app URL → **Connect Google Ads** → choose an account → **Run audit**.

The exact redirect URI the app expects is printed on its home page, so you can copy it from there.

## Who can log in
While the OAuth app is in *Testing* mode, only Google accounts listed under
Google Cloud → **Google Auth Platform → Audience → Test users** (max 100) can sign in.
To let anyone sign in you must add a privacy policy + homepage and submit the app for
Google verification (the `adwords` scope is sensitive).

## Common errors

| What you see | Fix |
|---|---|
| "Almost there — finish setup" page | Add the missing env vars in Vercel → Settings → Environment Variables, then Deployments → ⋯ → **Redeploy** |
| `redirect_uri_mismatch` from Google | Step 3 not done, or a typo. The URI must match exactly, including `https://` and `/auth/google/callback` |
| *Access blocked: app has not completed verification* | Add your Google account as a test user |
| `CLOUD_PROJECT_NOT_APPROVED_FOR_PRODUCTION` | Cloud project still at Test access; wait for Explorer or apply for Basic |
| `RESOURCE_EXHAUSTED` | Daily API limit (Explorer = 2,880 ops). Apply for Basic access |
| Audit times out on a very large account | Increase `maxDuration` in `vercel.json` (Pro plan allows up to 300 s) |

## Updating the app later
Edit a file on GitHub (pencil icon) → *Commit changes*. Vercel redeploys automatically in ~1 minute.
Audit rules and thresholds are in `api/audit.py` (the `CONFIG` dictionary at the top).

## Run on your own computer instead
Install Python 3.12, copy `.env.example` to `.env` and fill it in, then:
```
pip install -r requirements.txt
python api/index.py
```
Open http://localhost:3000 (the localhost URIs are already in your OAuth client).
