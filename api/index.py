"""
api/index.py — Google Ads Audit Tool, single-file version (v2: 5 audit types).

Everything is in this one file so it can be uploaded to GitHub in one go:
  1. HTML templates      (TEMPLATES dict)
  2. Audit engine        (data pull + 18 rules; thresholds in CONFIG; AUDIT_TYPES)
  3. FastAPI web app     (OAuth login, account list, audit chooser, report)

Runs on Vercel as a serverless function, or locally with:  python api/index.py
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

from dotenv import load_dotenv

load_dotenv()

os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from google.ads.googleads.client import GoogleAdsClient
from google_auth_oauthlib.flow import Flow
from jinja2 import DictLoader, Environment
from starlette.middleware.sessions import SessionMiddleware


# =============================================================================
# 1. TEMPLATES
# =============================================================================
TEMPLATES = {
    "base.html": r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}Google Ads Audit Tool{% endblock %}</title>
<style>
  :root{--navy:#0f3d8a;--navy-2:#0b2a63;--amber:#ffb547;--sky:#8fb3ff;--bg:#f3f5f9;--card:#fff;
        --ink:#14203a;--muted:#5f6b85;--line:#e3e8f0;--high:#d92d20;--med:#dc8a10;--low:#2563eb;--ok:#12934f}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Segoe UI",-apple-system,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5}
  header{background:var(--navy);color:#fff;padding:0 32px;height:64px;display:flex;justify-content:space-between;align-items:center}
  .brand{display:flex;align-items:center;gap:12px;color:#fff;text-decoration:none;font-weight:700;font-size:17px;letter-spacing:.01em}
  .mark{width:36px;height:36px;border-radius:10px;background:var(--navy-2);display:grid;place-items:center}
  header nav a{color:#c7d6f5;text-decoration:none;font-size:14px;margin-left:22px}
  header nav a:hover{color:#fff}
  .hero{background:var(--navy);color:#fff;padding:28px 32px 36px;margin-bottom:-24px}
  .hero .wrap{max-width:1080px;margin:0 auto}
  .hero h1{color:#fff}
  .hero p{color:#c7d6f5;margin:0}
  main{max-width:1080px;margin:32px auto;padding:0 24px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 28px;margin-bottom:20px;box-shadow:0 1px 2px rgba(20,32,58,.04)}
  h1{font-size:28px;margin:0 0 6px;letter-spacing:-.01em}h2{font-size:18px;margin:0 0 14px}
  .eyebrow{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--amber)}
  p.muted{color:var(--muted);margin:0 0 16px}
  .btn{display:inline-block;background:var(--navy);color:#fff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600;border:0;cursor:pointer;font-size:15px}
  .btn.amber{background:var(--amber);color:var(--ink)}
  .btn.secondary{background:#fff;color:var(--ink);border:1px solid var(--line)}
  .btn.small{padding:8px 14px;font-size:14px;border-radius:8px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .tag{display:inline-block;padding:3px 11px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
  .tag.High{background:var(--high)}.tag.Medium{background:var(--med)}.tag.Low{background:var(--low)}.tag.ok{background:var(--ok)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
  .stat{background:var(--bg);border-radius:12px;padding:16px}
  .stat .v{font-size:24px;font-weight:700;letter-spacing:-.01em}.stat .l{font-size:12px;color:var(--muted);margin-top:2px}
  .types{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
  .type{display:flex;gap:16px;padding:20px;border:1px solid var(--line);border-radius:14px;text-decoration:none;color:var(--ink);background:#fff;transition:border-color .15s,box-shadow .15s}
  .type:hover{border-color:var(--navy);box-shadow:0 4px 14px rgba(15,61,138,.10)}
  .type .ico{width:48px;height:48px;border-radius:12px;background:#eaf0fb;display:grid;place-items:center;flex:none}
  .type b{display:block;font-size:16px;margin-bottom:2px}.type small{color:var(--muted);font-size:13px}
  .type.primary{background:var(--navy);color:#fff;border-color:var(--navy)}.type.primary .ico{background:var(--navy-2)}.type.primary small{color:#c7d6f5}
  .score{display:flex;align-items:center;gap:28px}
  .ring{position:relative;width:140px;height:140px;flex:none}
  .ring svg{transform:rotate(-90deg)}
  .ring .n{position:absolute;inset:0;display:grid;place-items:center;font-size:38px;font-weight:800;color:#fff}
  .finding{border:1px solid var(--line);border-left:6px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
  .finding.High{border-left-color:var(--high)}.finding.Medium{border-left-color:var(--med)}.finding.Low{border-left-color:var(--low)}
  .finding h3{margin:6px 0 6px;font-size:17px}
  .fix{background:#eaf0fb;border-radius:10px;padding:12px 16px;margin:12px 0 4px;font-size:14px}
  .fix b{color:var(--navy)}
  details summary{cursor:pointer;color:var(--navy);font-size:14px;margin:8px 0 4px;font-weight:600}
  .scroll{overflow-x:auto}
  code{background:#eaf0fb;padding:1px 6px;border-radius:5px;font-size:13px}
  .footer{color:var(--muted);font-size:13px;text-align:center;margin:28px 0}
  @media print{header,.noprint,.hero{display:none}body{background:#fff}.card{border:0;padding:0;box-shadow:none}
               details{display:block}details summary{display:none}details>*{display:block}}
</style>
</head>
<body>
<header>
  <a class="brand" href="/"><span class="mark">
    <svg width="22" height="22" viewBox="0 0 176 176" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="26" y="96" width="22" height="46" rx="5" fill="#8fb3ff"/><rect x="58" y="70" width="22" height="72" rx="5" fill="#8fb3ff"/><rect x="90" y="48" width="22" height="94" rx="5" fill="#8fb3ff"/><circle cx="112" cy="64" r="40" fill="#0b2a63" stroke="#ffb547" stroke-width="12"/><path d="M141 93 L166 118" stroke="#ffb547" stroke-width="14" stroke-linecap="round"/><path d="M94 65 L106 77 L130 51" stroke="#ffb547" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </span>Google Ads Audit Tool</a>
  <nav>{% block nav %}{% endblock %}</nav>
</header>
{% block hero %}{% endblock %}
<main>{% block body %}{% endblock %}</main>
<p class="footer noprint">Read-only · nothing in your Google Ads account is changed</p>
</body>
</html>
""",
    "index.html": r"""{% extends "base.html" %}
{% block body %}
<div class="card" style="text-align:center;padding:64px 32px">
  <div class="eyebrow">Free · read-only · 2 minutes</div>
  <h1 style="font-size:36px;margin-top:8px">Audit your Google Ads account in one click</h1>
  <p class="muted" style="max-width:560px;margin:0 auto 26px">Connect the Google account that manages your ads, choose an account and an audit type, and get a scored report with exact fixes.</p>
  <a class="btn amber" href="/auth/google" style="font-size:16px;padding:14px 28px">Connect Google Ads</a>
  <div class="types" style="margin-top:44px;text-align:left">
    <div class="type"><div class="ico">{{ icon("overall") }}</div><div><b>Overall audit</b><small>Every check in one report</small></div></div>
    <div class="type"><div class="ico">{{ icon("conversions") }}</div><div><b>Conversions</b><small>Is tracking working and bidding aligned?</small></div></div>
    <div class="type"><div class="ico">{{ icon("waste") }}</div><div><b>Wasted budget</b><small>Where money leaks out</small></div></div>
    <div class="type"><div class="ico">{{ icon("ctr") }}</div><div><b>Low CTR</b><small>Why people aren't clicking</small></div></div>
    <div class="type"><div class="ico">{{ icon("keywords") }}</div><div><b>Low-performing keywords</b><small>Keywords that cost more than they return</small></div></div>
  </div>
  <p class="muted" style="margin-top:28px;font-size:12px">OAuth redirect URI: <code>{{ redirect_uri }}</code></p>
</div>
{% endblock %}
""",
    "accounts.html": r"""{% extends "base.html" %}
{% block nav %}<a href="/logout">Log out</a>{% endblock %}
{% block hero %}<div class="hero"><div class="wrap"><div class="eyebrow">Step 1 of 2</div><h1>Choose an account</h1><p>Every non-manager account this Google login can reach.</p></div></div>{% endblock %}
{% block body %}
<div class="card">
  {% if accounts %}
  <table>
    <tr><th>Account</th><th>ID</th><th>Currency</th><th>Access</th><th></th></tr>
    {% for a in accounts %}
    <tr>
      <td><b>{{ a.name }}</b></td>
      <td>{{ a.id[:3] }}-{{ a.id[3:6] }}-{{ a.id[6:] }}</td>
      <td>{{ a.currency }}</td>
      <td>{{ "via manager" if a.via_mcc else "direct" }}</td>
      <td style="text-align:right"><a class="btn small" href="/choose/{{ a.id }}?login={{ a.login }}">Choose audit →</a></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p><b>No accounts found.</b> This Google login is not a user on any Google Ads account.
     Add it in Google Ads → Admin → Access and security, or log in with a different Google account.</p>
  {% endif %}
  {% if errors %}
  <details style="margin-top:16px"><summary>{{ errors|length }} account(s) could not be read</summary>
    <ul>{% for e in errors %}<li><code>{{ e }}</code></li>{% endfor %}</ul></details>
  {% endif %}
</div>
{% endblock %}
""",
    "choose.html": r"""{% extends "base.html" %}
{% block nav %}<a href="/accounts">Accounts</a><a href="/logout">Log out</a>{% endblock %}
{% block hero %}<div class="hero"><div class="wrap"><div class="eyebrow">Step 2 of 2</div><h1>What do you want to audit?</h1><p>Account {{ customer_id[:3] }}-{{ customer_id[3:6] }}-{{ customer_id[6:] }} · last 30 days</p></div></div>{% endblock %}
{% block body %}
<div class="card">
  <div class="types">
    {% for key, t in types.items() %}
    <a class="type {{ 'primary' if key == 'overall' else '' }}" href="/audit/{{ customer_id }}?login={{ login }}&type={{ key }}">
      <div class="ico">{{ icon(key) }}</div>
      <div><b>{{ t.name }}</b><small>{{ t.description }}</small></div>
    </a>
    {% endfor %}
  </div>
</div>
{% endblock %}
""",
    "error.html": r"""{% extends "base.html" %}
{% block nav %}<a href="/accounts">Accounts</a><a href="/logout">Log out</a>{% endblock %}
{% block body %}
<div class="card">
  <div class="eyebrow" style="color:var(--high)">Something went wrong</div>
  <h1>{{ title }}</h1>
  {% if hints %}
  <div class="fix"><b>Likely cause</b><ul style="margin:6px 0 0">{% for h in hints %}<li>{{ h }}</li>{% endfor %}</ul></div>
  {% endif %}
  <details open><summary>Technical details</summary>
    <pre style="white-space:pre-wrap;font-size:13px;background:#f3f5f9;padding:12px;border-radius:8px">{{ message }}</pre>
  </details>
  <p><a class="btn secondary" href="/accounts">Back to accounts</a></p>
</div>
{% endblock %}
""",
    "report.html": r"""{% extends "base.html" %}
{% set a = r.account %}
{% block title %}{{ r.audit_name }} — {{ a.name }}{% endblock %}
{% block nav %}<a href="/choose/{{ r.customer_id }}?login={{ login }}">Other audits</a><a href="/accounts">Accounts</a><a href="#" onclick="window.print();return false">Print / PDF</a><a href="/logout">Log out</a>{% endblock %}
{% block body %}
{% set colour = "#12934f" if r.score >= 80 else ("#dc8a10" if r.score >= 55 else "#d92d20") %}
{% set dash = 408 * r.score / 100 %}
<div class="card" style="background:var(--navy);color:#fff;border:0">
  <div class="score">
    <div class="ring">
      <svg width="140" height="140" viewBox="0 0 140 140"><circle cx="70" cy="70" r="65" stroke="#0b2a63" stroke-width="10" fill="none"/><circle cx="70" cy="70" r="65" stroke="{{ colour }}" stroke-width="10" fill="none" stroke-linecap="round" stroke-dasharray="{{ '%.1f'|format(dash) }} 408"/></svg>
      <div class="n">{{ r.score }}</div>
    </div>
    <div>
      <div class="eyebrow">{{ r.audit_name }}</div>
      <h1 style="color:#fff">{{ a.name }}</h1>
      <p style="margin:0;color:#c7d6f5">ID {{ r.customer_id[:3] }}-{{ r.customer_id[3:6] }}-{{ r.customer_id[6:] }} · {{ today }} · last 30 days · {{ r.checks_run }} checks · {{ r.campaign_count }} campaigns, {{ r.keyword_count }} keywords, {{ r.ad_count }} ads</p>
      <p style="margin:10px 0 0">
        <span class="tag High">{{ r.counts.High }} high</span>
        <span class="tag Medium">{{ r.counts.Medium }} medium</span>
        <span class="tag Low">{{ r.counts.Low }} low</span>
        <span class="tag ok">{{ r.passed|length }} passed</span>
      </p>
    </div>
  </div>
</div>

<div class="card">
  <h2>30-day performance</h2>
  <div class="grid">
    <div class="stat"><div class="v">{{ "{:,.2f}".format(a.cost) }}</div><div class="l">Spend ({{ a.currency }})</div></div>
    <div class="stat"><div class="v">{{ "{:,}".format(a.clicks) }}</div><div class="l">Clicks</div></div>
    <div class="stat"><div class="v">{{ "{:,}".format(a.impressions) }}</div><div class="l">Impressions</div></div>
    <div class="stat"><div class="v">{{ a.ctr }}%</div><div class="l">CTR</div></div>
    <div class="stat"><div class="v">{{ a.avg_cpc }}</div><div class="l">Avg. CPC</div></div>
    <div class="stat"><div class="v">{{ a.conversions }}</div><div class="l">Conversions</div></div>
    <div class="stat"><div class="v">{{ a.cpa if a.cpa is not none else "–" }}</div><div class="l">Cost / conversion</div></div>
    <div class="stat"><div class="v">{{ a.conv_rate }}%</div><div class="l">Conv. rate</div></div>
  </div>
</div>

<div class="card">
  <h2>Findings</h2>
  {% if not r.findings %}<p>No issues found by this audit's checks. Nice account.</p>{% endif %}
  {% for f in r.findings %}
  <div class="finding {{ f.severity }}">
    <span class="tag {{ f.severity }}">{{ f.severity }}</span>
    <h3>{{ f.title }}</h3>
    <p style="margin:0 0 6px;color:var(--muted)">{{ f.detail }}</p>
    <div class="fix"><b>Fix:</b> {{ f.fix }}</div>
    {% if f.examples %}
    <details><summary>Show {{ f.examples|length }} example row(s)</summary>
      <div class="scroll"><table>
        <tr>{% for c in f.columns %}<th>{{ c }}</th>{% endfor %}</tr>
        {% for row in f.examples %}<tr>{% for c in f.columns %}<td>{{ row[c] }}</td>{% endfor %}</tr>{% endfor %}
      </table></div>
    </details>
    {% endif %}
  </div>
  {% endfor %}
</div>

{% if r.passed %}
<div class="card">
  <h2>Checks passed</h2>
  <p>{% for p in r.passed %}<span class="tag ok" style="margin:0 6px 6px 0">{{ p }}</span>{% endfor %}</p>
</div>
{% endif %}
<p class="muted noprint" style="font-size:13px">Score = 100 − 15 per High, 7 per Medium, 3 per Low finding, over the checks in this audit type.</p>
{% endblock %}
""",
    "setup.html": r"""{% extends "base.html" %}
{% block body %}
<div class="card">
  <div class="eyebrow">Setup</div>
  <h1>Almost there — finish setup</h1>
  <p class="muted">The app is deployed but these settings are missing:</p>
  <ul>{% for m in missing %}<li><code>{{ m }}</code></li>{% endfor %}</ul>
  <div class="fix"><b>On Vercel:</b> Project → Settings → Environments → Production → Environment Variables → add each one → then Deployments → ⋯ → <b>Redeploy</b>.<br>
    <b>Locally:</b> copy <code>.env.example</code> to <code>.env</code> and fill it in.</div>
  <h2 style="margin-top:20px">Google Cloud OAuth client must also allow</h2>
  <table>
    <tr><th>Authorized JavaScript origin</th><td><code>{{ base_url }}</code></td></tr>
    <tr><th>Authorized redirect URI</th><td><code>{{ redirect_uri }}</code></td></tr>
  </table>
</div>
{% endblock %}
""",
}


# =============================================================================
# 2. AUDIT ENGINE
# =============================================================================


# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------
CONFIG = {
    "burn_min_clicks": 3,          # search term needs at least this many clicks
    "burn_cpa_multiplier": 2.0,    # ...and cost >= this x account CPA
    "burn_high_multiplier": 4.0,   # cost >= this x CPA => High instead of Medium
    "burn_fallback_cost": 50.0,    # if account has no conversions, flag terms costing >= this
    "budget_lost_is": 0.10,        # >= 10% search IS lost to budget
    "rank_lost_is": 0.30,          # >= 30% search IS lost to rank
    "qs_threshold": 5,             # QS below this is flagged
    "qs_high_share": 0.30,         # >= 30% of keywords low QS => High
    "rsa_min_headlines": 8,
    "rsa_min_descriptions": 3,
    "min_asset_types": 4,
    "smart_bidding_min_conv": 30,
    "max_examples": 15,            # rows shown per finding in the report
    "low_ctr_campaign": 0.02,      # search campaign CTR below 2%
    "low_ctr_campaign_min_impr": 100,
    "low_ctr_keyword": 0.01,       # keyword CTR below 1%
    "low_ctr_keyword_min_impr": 200,
    "zero_conv_spend_multiplier": 2.0,  # campaign/keyword spend >= this x CPA with 0 conversions
}

WEIGHTS = {"High": 15, "Medium": 7, "Low": 3}

SMART_BIDDING = {
    "TARGET_CPA", "TARGET_ROAS", "MAXIMIZE_CONVERSIONS", "MAXIMIZE_CONVERSION_VALUE",
}
TARGET_BIDDING = {"TARGET_CPA", "TARGET_ROAS"}
VOLUME_BIDDING = {"MANUAL_CPC", "TARGET_SPEND", "MAXIMIZE_CLICKS"}


@dataclass
class Finding:
    rule: str
    severity: str            # High / Medium / Low
    title: str
    detail: str
    fix: str
    examples: list[dict] = field(default_factory=list)   # rows for a table
    columns: list[str] = field(default_factory=list)     # column headers


# ---------------------------------------------------------------------------
# Client + data pull
# ---------------------------------------------------------------------------
def build_client(refresh_token: str, login_customer_id: str | None = None) -> GoogleAdsClient:
    cfg = {
        "developer_token": os.getenv("GOOGLE_DEVELOPER_TOKEN", "NOT_NEEDED_SINCE_SEPT_2026"),
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
        "refresh_token": refresh_token,
        "use_proto_plus": True,
    }
    if login_customer_id:
        cfg["login_customer_id"] = str(login_customer_id).replace("-", "")
    return GoogleAdsClient.load_from_dict(cfg)


def _query(client: GoogleAdsClient, customer_id: str, gaql: str):
    service = client.get_service("GoogleAdsService")
    stream = service.search_stream(customer_id=customer_id, query=gaql)
    for batch in stream:
        for row in batch.results:
            yield row


def _money(micros: int | None) -> float:
    return round((micros or 0) / 1_000_000, 2)


def list_accessible_accounts(refresh_token: str) -> tuple[list[dict], list[str]]:
    """Every non-manager account the login can reach, expanding MCC trees."""
    client = build_client(refresh_token)
    cs = client.get_service("CustomerService")
    accessible = cs.list_accessible_customers().resource_names
    seen: dict[str, dict] = {}
    errors: list[str] = []

    for rn in accessible:
        login_id = rn.split("/")[-1]
        sub = build_client(refresh_token, login_customer_id=login_id)
        gaql = """
            SELECT customer_client.id, customer_client.descriptive_name,
                   customer_client.manager, customer_client.level,
                   customer_client.status, customer_client.currency_code,
                   customer_client.time_zone
            FROM customer_client
            WHERE customer_client.status = 'ENABLED'
        """
        try:
            for row in _query(sub, login_id, gaql):
                cc = row.customer_client
                if cc.manager:
                    continue
                cid = str(cc.id)
                if cid not in seen:
                    seen[cid] = {
                        "id": cid,
                        "name": cc.descriptive_name or f"Account {cid}",
                        "currency": cc.currency_code,
                        "login": login_id,
                        "via_mcc": login_id != cid,
                    }
        except Exception as e:  # cancelled / suspended accounts throw; skip them
            errors.append(f"{login_id}: {str(e).splitlines()[0][:120]}")
    accounts = sorted(seen.values(), key=lambda a: a["name"].lower())
    return accounts, errors


def pull_data(refresh_token: str, customer_id: str, login_customer_id: str | None) -> dict[str, Any]:
    client = build_client(refresh_token, login_customer_id)
    cid = str(customer_id).replace("-", "")
    q = lambda g: list(_query(client, cid, g))  # noqa: E731

    data: dict[str, Any] = {"customer_id": cid}

    # 1. Account summary, last 30 days
    rows = q("""
        SELECT customer.id, customer.descriptive_name, customer.currency_code,
               customer.time_zone, metrics.clicks, metrics.impressions,
               metrics.cost_micros, metrics.conversions, metrics.conversions_value,
               metrics.ctr, metrics.average_cpc
        FROM customer WHERE segments.date DURING LAST_30_DAYS
    """)
    if rows:
        r = rows[0]
        m = r.metrics
        conv = m.conversions or 0
        cost = _money(m.cost_micros)
        data["account"] = {
            "name": r.customer.descriptive_name or cid,
            "currency": r.customer.currency_code,
            "time_zone": r.customer.time_zone,
            "clicks": m.clicks,
            "impressions": m.impressions,
            "cost": cost,
            "conversions": round(conv, 1),
            "conv_value": round(m.conversions_value or 0, 2),
            "ctr": round((m.ctr or 0) * 100, 2),
            "avg_cpc": _money(m.average_cpc),
            "cpa": round(cost / conv, 2) if conv else None,
            "conv_rate": round(conv / m.clicks * 100, 2) if m.clicks else 0,
        }
    else:
        data["account"] = {"name": cid, "currency": "", "clicks": 0, "impressions": 0,
                           "cost": 0, "conversions": 0, "conv_value": 0, "ctr": 0,
                           "avg_cpc": 0, "cpa": None, "conv_rate": 0, "time_zone": ""}

    # 2. Conversion actions
    data["conversion_actions"] = [
        {"name": r.conversion_action.name, "type": r.conversion_action.type_.name,
         "primary": r.conversion_action.primary_for_goal,
         "counted": r.conversion_action.include_in_conversions_metric}
        for r in q("""
            SELECT conversion_action.name, conversion_action.type,
                   conversion_action.primary_for_goal,
                   conversion_action.include_in_conversions_metric
            FROM conversion_action WHERE conversion_action.status = 'ENABLED'
        """)
    ]

    # 3. Campaigns
    data["campaigns"] = []
    for r in q("""
        SELECT campaign.id, campaign.name, campaign.advertising_channel_type,
               campaign.bidding_strategy_type, campaign_budget.amount_micros,
               metrics.clicks, metrics.impressions, metrics.cost_micros,
               metrics.conversions, metrics.search_impression_share,
               metrics.search_budget_lost_impression_share,
               metrics.search_rank_lost_impression_share
        FROM campaign
        WHERE campaign.status = 'ENABLED' AND segments.date DURING LAST_30_DAYS
    """):
        c, m = r.campaign, r.metrics
        data["campaigns"].append({
            "id": str(c.id), "name": c.name,
            "channel": c.advertising_channel_type.name,
            "bidding": c.bidding_strategy_type.name,
            "daily_budget": _money(r.campaign_budget.amount_micros),
            "clicks": m.clicks, "impressions": m.impressions,
            "cost": _money(m.cost_micros), "conversions": round(m.conversions or 0, 1),
            "is": m.search_impression_share or 0,
            "is_lost_budget": m.search_budget_lost_impression_share or 0,
            "is_lost_rank": m.search_rank_lost_impression_share or 0,
        })

    # 4. Keywords
    data["keywords"] = []
    for r in q("""
        SELECT campaign.id, campaign.name, campaign.bidding_strategy_type,
               ad_group.id, ad_group.name,
               ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type,
               ad_group_criterion.quality_info.quality_score,
               metrics.clicks, metrics.impressions, metrics.cost_micros, metrics.conversions
        FROM keyword_view
        WHERE segments.date DURING LAST_30_DAYS
          AND campaign.status = 'ENABLED' AND ad_group.status = 'ENABLED'
          AND ad_group_criterion.status = 'ENABLED'
          AND ad_group_criterion.negative = FALSE
    """):
        k, m = r.ad_group_criterion, r.metrics
        data["keywords"].append({
            "campaign_id": str(r.campaign.id), "campaign": r.campaign.name,
            "bidding": r.campaign.bidding_strategy_type.name,
            "ad_group_id": str(r.ad_group.id), "ad_group": r.ad_group.name,
            "keyword": k.keyword.text, "match": k.keyword.match_type.name,
            "qs": k.quality_info.quality_score or None,
            "clicks": m.clicks, "impressions": m.impressions,
            "cost": _money(m.cost_micros), "conversions": round(m.conversions or 0, 1),
        })

    # 5. Search terms
    data["search_terms"] = []
    for r in q(f"""
        SELECT campaign.name, ad_group.name, search_term_view.search_term,
               metrics.clicks, metrics.cost_micros, metrics.conversions
        FROM search_term_view
        WHERE segments.date DURING LAST_30_DAYS AND campaign.status = 'ENABLED'
          AND metrics.clicks >= {CONFIG['burn_min_clicks']}
    """):
        m = r.metrics
        data["search_terms"].append({
            "campaign": r.campaign.name, "ad_group": r.ad_group.name,
            "term": r.search_term_view.search_term, "clicks": m.clicks,
            "cost": _money(m.cost_micros), "conversions": round(m.conversions or 0, 1),
        })

    # 6. Ads
    data["ads"] = []
    for r in q("""
        SELECT campaign.id, campaign.name, ad_group.id, ad_group.name,
               ad_group_ad.ad.id, ad_group_ad.ad.type,
               ad_group_ad.policy_summary.approval_status, ad_group_ad.ad_strength,
               ad_group_ad.ad.responsive_search_ad.headlines,
               ad_group_ad.ad.responsive_search_ad.descriptions
        FROM ad_group_ad
        WHERE campaign.status = 'ENABLED' AND ad_group.status = 'ENABLED'
          AND ad_group_ad.status = 'ENABLED'
    """):
        a = r.ad_group_ad
        rsa = a.ad.responsive_search_ad
        data["ads"].append({
            "campaign_id": str(r.campaign.id), "campaign": r.campaign.name,
            "ad_group_id": str(r.ad_group.id), "ad_group": r.ad_group.name,
            "ad_id": str(a.ad.id), "type": a.ad.type_.name,
            "approval": a.policy_summary.approval_status.name,
            "strength": a.ad_strength.name,
            "headlines": len(rsa.headlines), "descriptions": len(rsa.descriptions),
        })

    # 7. Assets (extensions) at campaign and account level
    data["campaign_assets"] = {}
    for r in q("""
        SELECT campaign.id, campaign_asset.field_type
        FROM campaign_asset
        WHERE campaign_asset.status = 'ENABLED' AND campaign.status = 'ENABLED'
    """):
        data["campaign_assets"].setdefault(str(r.campaign.id), set()).add(
            r.campaign_asset.field_type.name)
    data["account_assets"] = {
        r.customer_asset.field_type.name
        for r in q("SELECT customer_asset.field_type FROM customer_asset "
                   "WHERE customer_asset.status = 'ENABLED'")
    }

    # 8. Negatives: campaign-level keywords and shared lists
    data["campaign_negatives"] = {}
    for r in q("""
        SELECT campaign.id FROM campaign_criterion
        WHERE campaign_criterion.negative = TRUE AND campaign_criterion.type = 'KEYWORD'
          AND campaign.status = 'ENABLED'
    """):
        k = str(r.campaign.id)
        data["campaign_negatives"][k] = data["campaign_negatives"].get(k, 0) + 1
    data["campaigns_with_neg_list"] = {
        str(r.campaign.id) for r in q("""
            SELECT campaign.id FROM campaign_shared_set
            WHERE shared_set.type = 'NEGATIVE_KEYWORDS'
              AND campaign_shared_set.status = 'ENABLED' AND campaign.status = 'ENABLED'
        """)
    }

    # 9. Ad groups (search only)
    data["ad_groups"] = [
        {"id": str(r.ad_group.id), "name": r.ad_group.name,
         "campaign_id": str(r.campaign.id), "campaign": r.campaign.name}
        for r in q("""
            SELECT campaign.id, campaign.name, ad_group.id, ad_group.name
            FROM ad_group
            WHERE ad_group.status = 'ENABLED' AND campaign.status = 'ENABLED'
              AND campaign.advertising_channel_type = 'SEARCH'
        """)
    ]
    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _search_campaigns(data):
    return [c for c in data["campaigns"] if c["channel"] == "SEARCH"]


def _ex(rows):
    return rows[: CONFIG["max_examples"]]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
def rule_conversion_tracking(data):
    acts = data["conversion_actions"]
    acc = data["account"]
    if not acts:
        return [Finding("1", "High", "No conversion tracking",
                        "The account has no enabled conversion actions. Every bidding decision is blind.",
                        "Create at least one conversion action (form submit, call, purchase) via Google Tag "
                        "Manager or the Google tag, then switch campaigns to a conversion-based bid strategy.")]
    if acc["conversions"] == 0 and acc["clicks"] > 0:
        return [Finding("1", "High", "Zero conversions recorded in 30 days",
                        f"{len(acts)} conversion action(s) exist but recorded 0 conversions across "
                        f"{acc['clicks']} clicks. The tag is probably not firing.",
                        "Open Google Tag Assistant / GTM Preview and confirm the conversion tag fires on the "
                        "thank-you page or event. Check the action's status column in Goals → Conversions.",
                        examples=_ex([{"Action": a["name"], "Type": a["type"],
                                       "Primary": "Yes" if a["primary"] else "No"} for a in acts]),
                        columns=["Action", "Type", "Primary"])]
    return []


def rule_disapproved_ads(data):
    bad = [a for a in data["ads"] if a["approval"] in ("DISAPPROVED", "AREA_OF_INTEREST_ONLY")]
    if not bad:
        return []
    return [Finding("2", "High", f"{len(bad)} enabled ad(s) disapproved or limited",
                    "These ads are enabled but cannot serve fully, so their ad groups may be running "
                    "with reduced or no ads.",
                    "Open Ads & assets, filter by policy status, read the policy reason and either edit "
                    "the ad or appeal.",
                    examples=_ex([{"Campaign": a["campaign"], "Ad group": a["ad_group"],
                                   "Ad ID": a["ad_id"], "Status": a["approval"]} for a in bad]),
                    columns=["Campaign", "Ad group", "Ad ID", "Status"])]


def rule_burn_terms(data):
    cpa = data["account"]["cpa"]
    threshold = (cpa * CONFIG["burn_cpa_multiplier"]) if cpa else CONFIG["burn_fallback_cost"]
    burn = [t for t in data["search_terms"]
            if t["clicks"] >= CONFIG["burn_min_clicks"] and t["conversions"] == 0
            and t["cost"] >= threshold]
    if not burn:
        return []
    burn.sort(key=lambda t: -t["cost"])
    wasted = round(sum(t["cost"] for t in burn), 2)
    high_thr = (cpa * CONFIG["burn_high_multiplier"]) if cpa else CONFIG["burn_fallback_cost"] * 2
    sev = "High" if any(t["cost"] >= high_thr for t in burn) else "Medium"
    basis = f"{CONFIG['burn_cpa_multiplier']:.0f}× the account CPA ({cpa})" if cpa \
        else f"{CONFIG['burn_fallback_cost']} (no CPA available)"
    return [Finding("3", sev, f"{len(burn)} burn search term(s) wasting {wasted}",
                    f"Search terms with {CONFIG['burn_min_clicks']}+ clicks, zero conversions and cost of at "
                    f"least {basis}.",
                    "Add each term as an exact or phrase negative at campaign level (or to a shared "
                    "negative list). Review the search terms report weekly.",
                    examples=_ex([{"Search term": t["term"], "Campaign": t["campaign"],
                                   "Clicks": t["clicks"], "Cost": t["cost"]} for t in burn]),
                    columns=["Search term", "Campaign", "Clicks", "Cost"])]


def rule_broad_match(data):
    risky = [k for k in data["keywords"] if k["match"] == "BROAD" and k["bidding"] not in SMART_BIDDING]
    if not risky:
        return []
    risky.sort(key=lambda k: -k["cost"])
    return [Finding("4", "High", f"{len(risky)} broad match keyword(s) without Smart Bidding",
                    "Broad match relies on Smart Bidding signals to stay relevant. On Manual CPC or "
                    "Maximize Clicks it matches loosely and burns budget.",
                    "Either switch these campaigns to Maximize Conversions / tCPA (needs conversion data) "
                    "or change the keywords to phrase match.",
                    examples=_ex([{"Keyword": k["keyword"], "Campaign": k["campaign"],
                                   "Bidding": k["bidding"], "Cost": k["cost"]} for k in risky]),
                    columns=["Keyword", "Campaign", "Bidding", "Cost"])]


def rule_budget_limited(data):
    hit = [c for c in _search_campaigns(data) if c["is_lost_budget"] >= CONFIG["budget_lost_is"]]
    if not hit:
        return []
    hit.sort(key=lambda c: -c["is_lost_budget"])
    return [Finding("5", "Medium", f"{len(hit)} campaign(s) limited by budget",
                    f"Losing {CONFIG['budget_lost_is']:.0%}+ of search impression share to budget.",
                    "Raise the daily budget on campaigns that convert profitably, or move budget from "
                    "weaker campaigns. If the cap is intentional, ignore this.",
                    examples=_ex([{"Campaign": c["name"], "Daily budget": c["daily_budget"],
                                   "IS lost (budget)": f"{c['is_lost_budget']:.0%}",
                                   "Conversions": c["conversions"]} for c in hit]),
                    columns=["Campaign", "Daily budget", "IS lost (budget)", "Conversions"])]


def rule_rank_limited(data):
    hit = [c for c in _search_campaigns(data) if c["is_lost_rank"] >= CONFIG["rank_lost_is"]]
    if not hit:
        return []
    hit.sort(key=lambda c: -c["is_lost_rank"])
    return [Finding("6", "Medium", f"{len(hit)} campaign(s) limited by Ad Rank",
                    f"Losing {CONFIG['rank_lost_is']:.0%}+ of search impression share to Ad Rank "
                    "(bid × Quality Score).",
                    "Improve Quality Score (ad relevance, landing page) and/or raise bids or targets. "
                    "Check the Quality Score finding below.",
                    examples=_ex([{"Campaign": c["name"], "IS": f"{c['is']:.0%}",
                                   "IS lost (rank)": f"{c['is_lost_rank']:.0%}"} for c in hit]),
                    columns=["Campaign", "IS", "IS lost (rank)"])]


def rule_quality_score(data):
    scored = [k for k in data["keywords"] if k["qs"]]
    low = [k for k in scored if k["qs"] < CONFIG["qs_threshold"]]
    if not low:
        return []
    low.sort(key=lambda k: (k["qs"], -k["cost"]))
    share = len(low) / len(scored)
    sev = "High" if share >= CONFIG["qs_high_share"] else "Medium"
    return [Finding("7", sev, f"{len(low)} keyword(s) with Quality Score under {CONFIG['qs_threshold']} "
                    f"({share:.0%} of scored keywords)",
                    "Low QS raises CPC and lowers position. Usual causes: keyword not in the ad, "
                    "generic landing page, mixed intent in one ad group.",
                    "Move low-QS keywords into tighter ad groups, put the keyword in headline 1, "
                    "send traffic to a dedicated landing page, or pause them.",
                    examples=_ex([{"Keyword": k["keyword"], "Ad group": k["ad_group"], "QS": k["qs"],
                                   "Cost": k["cost"]} for k in low]),
                    columns=["Keyword", "Ad group", "QS", "Cost"])]


def rule_rsa_strength(data):
    rsas = [a for a in data["ads"] if a["type"] == "RESPONSIVE_SEARCH_AD"]
    weak = [a for a in rsas if a["strength"] in ("POOR", "AVERAGE")
            or a["headlines"] < CONFIG["rsa_min_headlines"]
            or a["descriptions"] < CONFIG["rsa_min_descriptions"]]
    if not weak:
        return []
    return [Finding("8", "Medium", f"{len(weak)} responsive search ad(s) need more assets",
                    f"Ads rated Poor/Average, or with fewer than {CONFIG['rsa_min_headlines']} headlines / "
                    f"{CONFIG['rsa_min_descriptions']} descriptions.",
                    "Add headlines until you have 10–15 distinct ones (keyword, benefit, CTA, social proof) "
                    "and 4 descriptions. Pin sparingly.",
                    examples=_ex([{"Campaign": a["campaign"], "Ad group": a["ad_group"],
                                   "Strength": a["strength"], "Headlines": a["headlines"],
                                   "Descriptions": a["descriptions"]} for a in weak]),
                    columns=["Campaign", "Ad group", "Strength", "Headlines", "Descriptions"])]


def rule_extensions(data):
    acct = data["account_assets"]
    thin = []
    for c in _search_campaigns(data):
        types = acct | data["campaign_assets"].get(c["id"], set())
        if len(types) < CONFIG["min_asset_types"]:
            thin.append({"Campaign": c["name"], "Asset types": len(types),
                         "Present": ", ".join(sorted(t.title() for t in types)) or "none"})
    if not thin:
        return []
    return [Finding("9", "Medium", f"{len(thin)} search campaign(s) with fewer than "
                    f"{CONFIG['min_asset_types']} asset types",
                    "Extensions (sitelinks, callouts, structured snippets, call, image…) lift Ad Rank "
                    "and CTR at no extra cost.",
                    "Add sitelinks (4+), callouts (4+), structured snippets and a call or lead-form asset "
                    "at account or campaign level.",
                    examples=_ex(thin), columns=["Campaign", "Asset types", "Present"])]


def rule_bidding_vs_volume(data):
    hit = []
    for c in _search_campaigns(data):
        n = CONFIG["smart_bidding_min_conv"]
        if c["bidding"] in TARGET_BIDDING and c["conversions"] < n:
            hit.append({"Campaign": c["name"], "Bidding": c["bidding"], "Conversions (30d)": c["conversions"],
                        "Issue": f"Target bidding with under {n} conversions"})
        elif c["bidding"] in VOLUME_BIDDING and c["conversions"] >= n:
            hit.append({"Campaign": c["name"], "Bidding": c["bidding"], "Conversions (30d)": c["conversions"],
                        "Issue": f"{n}+ conversions but not on Smart Bidding"})
    if not hit:
        return []
    return [Finding("10", "Medium", f"{len(hit)} campaign(s) with a bid strategy that doesn't match volume",
                    "Target CPA/ROAS needs ~30 conversions a month to learn; campaigns with plenty of "
                    "conversions should not still be on Manual CPC or Maximize Clicks.",
                    "Low volume → Maximize Conversions with no target (or Max Clicks). High volume → "
                    "Maximize Conversions with a tCPA close to the historical CPA.",
                    examples=_ex(hit), columns=["Campaign", "Bidding", "Conversions (30d)", "Issue"])]


def rule_negatives(data):
    missing = [c for c in _search_campaigns(data)
               if not data["campaign_negatives"].get(c["id"]) and c["id"] not in data["campaigns_with_neg_list"]]
    if not missing:
        return []
    return [Finding("11", "Medium", f"{len(missing)} search campaign(s) with no negative keywords",
                    "No campaign-level negatives and no shared negative list attached.",
                    "Create an account-level shared negative list (free, cheap, diy, jobs, how to, "
                    "reviews…) and attach it to every search campaign; add campaign negatives from the "
                    "search terms report.",
                    examples=_ex([{"Campaign": c["name"], "Cost (30d)": c["cost"]} for c in missing]),
                    columns=["Campaign", "Cost (30d)"])]


def rule_empty_ad_groups(data):
    ads_by_ag = {a["ad_group_id"] for a in data["ads"]}
    kws_by_ag = {k["ad_group_id"] for k in data["keywords"]}
    empty = []
    for ag in data["ad_groups"]:
        no_ads = ag["id"] not in ads_by_ag
        no_kws = ag["id"] not in kws_by_ag
        if no_ads or no_kws:
            empty.append({"Campaign": ag["campaign"], "Ad group": ag["name"],
                          "Missing": "ads and keywords" if no_ads and no_kws else ("ads" if no_ads else "keywords")})
    if not empty:
        return []
    return [Finding("12", "Low", f"{len(empty)} enabled ad group(s) with no active ads or keywords",
                    "These ad groups are enabled but cannot serve. They clutter the account and hide "
                    "structural problems.",
                    "Pause them, or add the missing ads / keywords.",
                    examples=_ex(empty), columns=["Campaign", "Ad group", "Missing"])]


def rule_zero_conversion_campaigns(data):
    cpa = data["account"]["cpa"]
    thr = (cpa * CONFIG["zero_conv_spend_multiplier"]) if cpa else CONFIG["burn_fallback_cost"]
    hit = [c for c in data["campaigns"] if c["conversions"] == 0 and c["cost"] >= thr]
    if not hit:
        return []
    hit.sort(key=lambda c: -c["cost"])
    wasted = round(sum(c["cost"] for c in hit), 2)
    return [Finding("13", "High", f"{len(hit)} campaign(s) spent {wasted} with zero conversions",
                    "Each of these spent at least " + (f"{CONFIG['zero_conv_spend_multiplier']:.0f}x the account CPA"
                    if cpa else f"{CONFIG['burn_fallback_cost']}") + " in 30 days without a single conversion.",
                    "Check conversion tracking on the landing pages these campaigns use, review their search terms, "
                    "and pause or restructure anything that cannot be justified.",
                    examples=_ex([{"Campaign": c["name"], "Cost": c["cost"], "Clicks": c["clicks"],
                                   "Bidding": c["bidding"]} for c in hit]),
                    columns=["Campaign", "Cost", "Clicks", "Bidding"])]


def rule_no_primary_conversion(data):
    acts = data["conversion_actions"]
    if acts and not any(a["primary"] for a in acts):
        return [Finding("14", "Medium", "No primary conversion action",
                        "Conversion actions exist but none is marked primary, so Smart Bidding has no goal "
                        "to optimise toward and the Conversions column may be empty.",
                        "In Goals → Conversions, open the action that represents a real lead or sale and set "
                        "it to Primary. Keep page views and micro-actions as Secondary.",
                        examples=_ex([{"Action": a["name"], "Type": a["type"]} for a in acts]),
                        columns=["Action", "Type"])]
    return []


def rule_low_ctr_campaigns(data):
    hit = []
    for c in _search_campaigns(data):
        if c["impressions"] >= CONFIG["low_ctr_campaign_min_impr"]:
            ctr = c["clicks"] / c["impressions"]
            if ctr < CONFIG["low_ctr_campaign"]:
                hit.append({"Campaign": c["name"], "CTR": f"{ctr:.2%}", "Impressions": c["impressions"],
                            "Clicks": c["clicks"]})
    if not hit:
        return []
    hit.sort(key=lambda r: r["CTR"])
    return [Finding("15", "Medium", f"{len(hit)} search campaign(s) with CTR under "
                    f"{CONFIG['low_ctr_campaign']:.0%}",
                    "Low CTR lowers expected-CTR in Quality Score, raising CPCs and dropping position.",
                    "Tighten keyword-to-ad relevance, add the keyword to headline 1, test stronger "
                    "offers/CTAs, add all extension types, and exclude irrelevant search terms.",
                    examples=_ex(hit), columns=["Campaign", "CTR", "Impressions", "Clicks"])]


def rule_low_ctr_keywords(data):
    hit = []
    for k in data["keywords"]:
        if k["impressions"] >= CONFIG["low_ctr_keyword_min_impr"]:
            ctr = k["clicks"] / k["impressions"]
            if ctr < CONFIG["low_ctr_keyword"]:
                hit.append({"Keyword": k["keyword"], "Match": k["match"], "Ad group": k["ad_group"],
                            "CTR": f"{ctr:.2%}", "Impressions": k["impressions"]})
    if not hit:
        return []
    hit.sort(key=lambda r: -r["Impressions"])
    return [Finding("16", "Medium", f"{len(hit)} keyword(s) with CTR under {CONFIG['low_ctr_keyword']:.0%}",
                    "High-impression keywords that people rarely click are usually too broad or mismatched "
                    "to the ad shown.",
                    "Move them to a tighter ad group with a matching ad, switch broad to phrase/exact, or "
                    "pause them.",
                    examples=_ex(hit), columns=["Keyword", "Match", "Ad group", "CTR", "Impressions"])]


def rule_keywords_spend_no_conversions(data):
    cpa = data["account"]["cpa"]
    thr = (cpa * CONFIG["zero_conv_spend_multiplier"]) if cpa else CONFIG["burn_fallback_cost"]
    hit = [k for k in data["keywords"] if k["conversions"] == 0 and k["cost"] >= thr]
    if not hit:
        return []
    hit.sort(key=lambda k: -k["cost"])
    wasted = round(sum(k["cost"] for k in hit), 2)
    return [Finding("17", "High", f"{len(hit)} keyword(s) spent {wasted} with zero conversions",
                    "Keywords that consumed at least " + (f"{CONFIG['zero_conv_spend_multiplier']:.0f}x CPA"
                    if cpa else f"{CONFIG['burn_fallback_cost']}") + " and returned nothing.",
                    "Pause them, or lower their bids and add negatives around them. Check whether the landing "
                    "page matches the intent.",
                    examples=_ex([{"Keyword": k["keyword"], "Match": k["match"], "Campaign": k["campaign"],
                                   "Cost": k["cost"], "Clicks": k["clicks"]} for k in hit]),
                    columns=["Keyword", "Match", "Campaign", "Cost", "Clicks"])]


def rule_top_wasted_spend_summary(data):
    """Informational Low finding: where the money without conversions went."""
    cpa = data["account"]["cpa"]
    rows = [c for c in data["campaigns"] if c["conversions"] == 0 and c["cost"] > 0]
    if not rows or cpa is None:
        return []
    total = round(sum(c["cost"] for c in rows), 2)
    share = total / data["account"]["cost"] if data["account"]["cost"] else 0
    if share < 0.10:
        return []
    return [Finding("18", "Low", f"{share:.0%} of spend ({total}) went to campaigns with no conversions",
                    "A summary of non-converting spend across the account.",
                    "Use the findings above to decide what to pause, fix or restructure.",
                    examples=_ex([{"Campaign": c["name"], "Cost": c["cost"]} for c in
                                  sorted(rows, key=lambda c: -c["cost"])]),
                    columns=["Campaign", "Cost"])]


AUDIT_TYPES = {
    "overall": {
        "name": "Overall audit",
        "tagline": "Every check in one report",
        "description": "All 12 core checks: tracking, ads, search terms, match types, budget, rank, Quality "
                       "Score, RSAs, extensions, bidding, negatives and structure.",
        "icon": "overall",
        "rules": None,   # None = every core rule
    },
    "conversions": {
        "name": "Conversions audit",
        "tagline": "Is tracking working and is bidding aligned?",
        "description": "Conversion actions, primary goals, campaigns spending without converting, and whether "
                       "bid strategies match conversion volume.",
        "icon": "conversions",
        "rules": ["rule_conversion_tracking", "rule_no_primary_conversion",
                  "rule_zero_conversion_campaigns", "rule_bidding_vs_volume", "rule_disapproved_ads"],
    },
    "waste": {
        "name": "Wasted budget audit",
        "tagline": "Where money leaks out",
        "description": "Burn search terms, broad match without Smart Bidding, missing negatives, "
                       "non-converting campaigns and keywords, and budget caps.",
        "icon": "waste",
        "rules": ["rule_burn_terms", "rule_keywords_spend_no_conversions", "rule_zero_conversion_campaigns",
                  "rule_broad_match", "rule_negatives", "rule_budget_limited", "rule_top_wasted_spend_summary"],
    },
    "ctr": {
        "name": "Low CTR audit",
        "tagline": "Why people aren't clicking",
        "description": "Campaigns and keywords with weak click-through rates, ad strength, extension coverage "
                       "and rank loss.",
        "icon": "ctr",
        "rules": ["rule_low_ctr_campaigns", "rule_low_ctr_keywords", "rule_rsa_strength",
                  "rule_extensions", "rule_rank_limited", "rule_disapproved_ads"],
    },
    "keywords": {
        "name": "Low-performing keywords",
        "tagline": "Keywords that cost more than they return",
        "description": "Low Quality Score, spend with no conversions, low CTR, broad match risk and empty ad "
                       "groups.",
        "icon": "keywords",
        "rules": ["rule_quality_score", "rule_keywords_spend_no_conversions", "rule_low_ctr_keywords",
                  "rule_broad_match", "rule_burn_terms", "rule_empty_ad_groups"],
    },
}


RULES = [
    rule_conversion_tracking, rule_disapproved_ads, rule_burn_terms, rule_broad_match,
    rule_budget_limited, rule_rank_limited, rule_quality_score, rule_rsa_strength,
    rule_extensions, rule_bidding_vs_volume, rule_negatives, rule_empty_ad_groups,
]

RULE_FUNC_IDS = {
    "1": "rule_conversion_tracking", "2": "rule_disapproved_ads", "3": "rule_burn_terms",
    "4": "rule_broad_match", "5": "rule_budget_limited", "6": "rule_rank_limited",
    "7": "rule_quality_score", "8": "rule_rsa_strength", "9": "rule_extensions",
    "10": "rule_bidding_vs_volume", "11": "rule_negatives", "12": "rule_empty_ad_groups",
    "13": "rule_zero_conversion_campaigns", "14": "rule_no_primary_conversion",
    "15": "rule_low_ctr_campaigns", "16": "rule_low_ctr_keywords",
    "17": "rule_keywords_spend_no_conversions", "18": "rule_top_wasted_spend_summary",
}

RULE_NAMES = {
    "1": "Conversion tracking", "2": "Disapproved ads", "3": "Burn search terms",
    "4": "Broad match risk", "5": "Budget limited", "6": "Rank limited", "7": "Quality Score",
    "8": "RSA strength", "9": "Extensions", "10": "Bidding vs volume", "11": "Negatives",
    "12": "Empty ad groups", "13": "Zero-conversion campaigns", "14": "Primary conversion set",
    "15": "Campaign CTR", "16": "Keyword CTR", "17": "Keyword spend vs conversions",
    "18": "Wasted spend share",
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_audit_for(refresh_token: str, customer_id: str, login_customer_id: str | None = None,
              audit_type: str = "overall") -> dict:
    spec = AUDIT_TYPES.get(audit_type) or AUDIT_TYPES["overall"]
    data = pull_data(refresh_token, customer_id, login_customer_id)
    if spec["rules"] is None:
        rules = list(RULES)
    else:
        rules = [globals()[name] for name in spec["rules"]]
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule(data))
    order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (order[f.severity], int(f.rule)))
    score = max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))
    checked = {r.__name__ for r in rules}
    rule_ids = {name: rid for rid, name in RULE_FUNC_IDS.items()}
    passed = [RULE_NAMES[rule_ids[n]] for n in checked
              if n in rule_ids and rule_ids[n] not in {f.rule for f in findings}]
    return {
        "account": data["account"],
        "customer_id": data["customer_id"],
        "audit_type": audit_type if audit_type in AUDIT_TYPES else "overall",
        "audit_name": spec["name"],
        "score": score,
        "findings": findings,
        "passed": sorted(passed),
        "counts": {s: sum(1 for f in findings if f.severity == s) for s in ("High", "Medium", "Low")},
        "campaign_count": len(data["campaigns"]),
        "keyword_count": len(data["keywords"]),
        "ad_count": len(data["ads"]),
        "checks_run": len(rules),
    }


# =============================================================================
# 3. WEB APP
# =============================================================================

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

api = FastAPI(title="Google Ads Audit Tool")
api.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET") or secrets.token_hex(32),
    max_age=60 * 60 * 24 * 30,
    same_site="lax",
    https_only=BASE_URL.startswith("https"),
)
templates = Jinja2Templates(env=Environment(loader=DictLoader(TEMPLATES), autoescape=True))

ICONS = {
    "overall": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0f3d8a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 13l3 3 5-6"/></svg>',
    "conversions": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0f3d8a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M21 12h-3"/></svg>',
    "waste": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0f3d8a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16l-1.5 12h-13z"/><path d="M9 7V4h6v3M10 11v5M14 11v5"/></svg>',
    "ctr": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0f3d8a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4l7 16 2-7 7-2z"/></svg>',
    "keywords": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0f3d8a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M17 12v3M20 12v2"/></svg>',
}


def icon(key: str):
    from markupsafe import Markup
    return Markup(ICONS.get(key, ICONS["overall"]))


templates.env.globals["icon"] = icon


@api.middleware("http")
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
@api.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("refresh_token"):
        return RedirectResponse("/accounts")
    return templates.TemplateResponse(request, "index.html", {"redirect_uri": REDIRECT_URI})


@api.get("/auth/google")
def auth_start(request: Request):
    flow = _flow()
    url, state = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true")
    request.session["oauth_state"] = state
    return RedirectResponse(url)


@api.get("/auth/google/callback")
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


@api.get("/accounts", response_class=HTMLResponse)
def accounts(request: Request):
    token = request.session.get("refresh_token")
    if not token:
        return RedirectResponse("/")
    try:
        accts, errors = list_accessible_accounts(token)
    except Exception as e:
        return _error(request, "Could not list Google Ads accounts", e)
    return templates.TemplateResponse(request, "accounts.html",
                                      {"accounts": accts, "errors": errors})


@api.get("/choose/{customer_id}", response_class=HTMLResponse)
def choose(request: Request, customer_id: str, login: str | None = None):
    if not request.session.get("refresh_token"):
        return RedirectResponse("/")
    return templates.TemplateResponse(request, "choose.html",
                                      {"customer_id": customer_id, "login": login or "",
                                       "types": AUDIT_TYPES})


@api.get("/audit/{customer_id}", response_class=HTMLResponse)
def audit_page(request: Request, customer_id: str, login: str | None = None, type: str = "overall"):
    token = request.session.get("refresh_token")
    if not token:
        return RedirectResponse("/")
    try:
        result = run_audit_for(token, customer_id, login, type)
    except Exception as e:
        return _error(request, "Audit failed", e)
    return templates.TemplateResponse(request, "report.html",
                                      {"r": result, "login": login or "",
                                       "today": date.today().strftime("%d %b %Y")})


@api.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


class VercelPathFix:
    """Vercel may hand the app the path '/api/index' (with the real page in ?__path=).
    Restore the real path so FastAPI routes work both on Vercel and locally."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "/")
            params = parse_qsl(scope.get("query_string", b"").decode(), keep_blank_values=True)
            forced = [v for k, v in params if k == "__path"]
            params = [(k, v) for k, v in params if k != "__path"]
            if forced:
                path = "/" + forced[0].lstrip("/")
            elif path.startswith("/api/index"):
                path = path[len("/api/index"):] or "/"
            scope["path"] = path
            scope["raw_path"] = path.encode()
            scope["query_string"] = urlencode(params).encode()
            scope["root_path"] = ""
        await self.inner(scope, receive, send)


app = VercelPathFix(api)


if __name__ == "__main__":
    print(f"\n  Google Ads Audit Tool running at {BASE_URL}\n  Press Ctrl+C to stop.\n")
    uvicorn.run(app, host="127.0.0.1", port=PORT)
