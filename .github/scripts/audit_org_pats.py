#!/usr/bin/env python3
"""
Audit org fine-grained PAT expirations using a GitHub App.

Env (required):
  - GH_APP_ID
  - GH_APP_PRIVATE_KEY            (PEM, multiline)   OR  GH_APP_PRIVATE_KEY_B64
  - ORG_NAME

Env (optional):
  - GH_APP_INSTALLATION_ID
  - SLACK_WEBHOOK_URL

CLI:
  --days N              Window to report (default: 30)
  --warn-threshold N    Mark as CRITICAL if days_left <= N (default: 7)
  --json PATH           Write findings JSON
  --md PATH             Write Markdown report
  --fail-on-findings    Exit 1 if any findings (useful for gating)
"""

from __future__ import annotations

import os
import sys
import time
import json
import logging
from argparse import ArgumentParser
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import jwt  # pyjwt
import requests
from dateutil.parser import isoparse

GITHUB_API = "https://api.github.com"

# ---------- logging ----------
LOG = logging.getLogger("org-pat-audit")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
LOG.setLevel(logging.INFO)
LOG.addHandler(_handler)


# ---------- helpers ----------
def getenv_strict(name: str) -> str:
    val = os.getenv(name)
    if not val:
        LOG.error("Missing required environment variable: %s", name)
        sys.exit(2)
    return val


def get_private_key_pem() -> str:
    """
    Return PEM string from GH_APP_PRIVATE_KEY or GH_APP_PRIVATE_KEY_B64.
    """
    pem = os.getenv("GH_APP_PRIVATE_KEY")
    if pem:
        return pem
    pem_b64 = os.getenv("GH_APP_PRIVATE_KEY_B64")
    if pem_b64:
        import base64
        try:
            return base64.b64decode(pem_b64).decode("utf-8")
        except Exception as e:
            LOG.error("Failed to decode GH_APP_PRIVATE_KEY_B64: %s", e)
            sys.exit(2)
    LOG.error("Missing GH_APP_PRIVATE_KEY (or GH_APP_PRIVATE_KEY_B64).")
    sys.exit(2)


def gh_app_jwt(app_id: str, pem: str) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}
    return jwt.encode(payload, pem, algorithm="RS256")


def gh_installation_token(jwt_bearer: str, org_name: str, install_id: Optional[str]) -> str:
    headers = {"Authorization": f"Bearer {jwt_bearer}", "Accept": "application/vnd.github+json"}

    if not install_id:
        # Discover installation for this org
        r = requests.get(f"{GITHUB_API}/app/installations", headers=headers, timeout=30)
        r.raise_for_status()
        installs = r.json() or []
        for inst in installs:
            acct = inst.get("account") or {}
            if (acct.get("login") or "").lower() == org_name.lower():
                install_id = str(inst.get("id"))
                break
        if not install_id:
            LOG.error("Could not find installation for org '%s'. Is the App installed?", org_name)
            sys.exit(3)

    r = requests.post(
        f"{GITHUB_API}/app/installations/{install_id}/access_tokens",
        headers=headers,
        timeout=30,
    )
    r.raise_for_status()
    tok = r.json().get("token")
    if not tok:
        LOG.error("Installation token response missing 'token'")
        sys.exit(4)
    return tok


def paged_get(url: str, headers: Dict[str, str]) -> List[Any]:
    items, page = [], 1
    while True:
        sep = "&" if "?" in url else "?"
        u = f"{url}{sep}page={page}&per_page=100"
        r = requests.get(u, headers=headers, timeout=30)
        if r.status_code == 404 and page == 1:
            return []  # endpoint variant not available
        r.raise_for_status()
        batch = r.json()
        if not isinstance(batch, list) or not batch:
            break
        items.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return items


def list_org_fg_pats(org: str, inst_token: str) -> list[dict]:
    """
    Lists approved fine-grained PATs that have access to org resources.
    Requires the GitHub App permission:
      Organization → Personal access tokens: Read
    GET /orgs/{org}/personal-access-tokens
    """
    headers = {"Authorization": f"token {inst_token}", "Accept": "application/vnd.github+json"}
    items, page = [], 1
    base = f"{GITHUB_API}/orgs/{org}/personal-access-tokens"
    while True:
        url = f"{base}?per_page=100&page={page}"
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 403:
            LOG.error("403 from list PATs API. Ensure the App has Organization → 'Personal access tokens: Read'.")
            r.raise_for_status()
        r.raise_for_status()
        batch = r.json() or []
        if not isinstance(batch, list) or not batch:
            break
        items.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    LOG.info("List PATs API returned %d item(s).", len(items))
    return items


def render_markdown(findings: List[Dict[str, Any]], org: str, window_days: int, warn_threshold: int) -> str:
    if not findings:
        return (
            f"# PAT Expiry Report\n\n"
            f"**Org:** `{org}`  \n"
            f"**Window:** {window_days} day(s)  •  **Warn if ≤** `{warn_threshold}` day(s)\n\n"
            f"No tokens expiring within the window.\n"
        )

    lines = [
        "# PAT Expiry Report",
        f"**Org:** `{org}`  ",
        f"**Window:** {window_days} day(s)  •  **Warn if ≤** `{warn_threshold}` day(s)",
        "",
        "| Severity | Days Left | Owner | Note | Expires | Last Used | Repos | Permissions | Token ID |",
        "|:--------:|----------:|------:|:-----|:--------|:----------|------:|:------------|:--------:|",
    ]
    for f in sorted(findings, key=lambda x: (x["severity"] != "CRITICAL", x["days_left"], x.get("owner") or "")):
        perms = ", ".join(f.get("permissions") or []) or "—"
        lines.append(
            f"| `{f['severity']}` "
            f"| {f['days_left']} "
            f"| `{f.get('owner') or 'unknown'}` "
            f"| {f.get('note') or '—'} "
            f"| `{f.get('expires_at')}` "
            f"| `{f.get('last_used_at') or '—'}` "
            f"| {f.get('repositories_count', 0)} "
            f"| {perms} "
            f"| `{f.get('id')}` |"
        )
    return "\n".join(lines) + "\n"


def slack_post(webhook: str, text: str) -> None:
    try:
        r = requests.post(webhook, json={"text": text}, timeout=15)
        r.raise_for_status()
    except Exception as e:
        LOG.error("Slack post failed: %s", e)


# ---------- main ----------
def main() -> None:
    ap = ArgumentParser(description="Audit org fine-grained PAT expirations (via GitHub App)")
    ap.add_argument("--days", type=int, default=30, help="Alert window in days (default: 30)")
    ap.add_argument(
        "--warn-threshold",
        type=int,
        default=7,
        help="Mark tokens as CRITICAL if remaining days <= this value (default: 7)",
    )
    ap.add_argument("--json", type=str, help="Write full JSON findings to this path")
    ap.add_argument("--md", type=str, help="Write Markdown report to this path")
    ap.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if anything is expiring within the window")
    args = ap.parse_args()

    # strict env
    app_id = getenv_strict("GH_APP_ID")
    org = getenv_strict("ORG_NAME")
    pem = get_private_key_pem()
    inst_id = os.getenv("GH_APP_INSTALLATION_ID")
    slack = os.getenv("SLACK_WEBHOOK_URL")

    # auth
    jwt_bearer = gh_app_jwt(app_id, pem)
    inst_token = gh_installation_token(jwt_bearer, org, inst_id)

    tokens = list_org_fg_pats(org, inst_token)
    if not isinstance(tokens, list):
        LOG.error("Unexpected API response shape (expected list).")
        sys.exit(5)

    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=args.days)

    findings = []
    for t in tokens:
        # NOTE: fields from GET /orgs/{org}/personal-access-tokens
        #   token_expires_at, token_last_used_at, token_name, token_id, owner{login}, permissions{}, repositories_url, access_granted_at, token_expired
        expiry = t.get("token_expires_at") or t.get("expires_at")  # support both just in case
        if not expiry:
            continue
        try:
            exp_dt = isoparse(expiry)
        except Exception:
            continue

        if exp_dt <= horizon:
            days_left = max(0, (exp_dt - now).days)
            severity = "CRITICAL" if days_left <= args.warn_threshold else "WARN"
            findings.append({
                "id": t.get("token_id") or t.get("id"),
                "owner": (t.get("owner") or {}).get("login"),
                "note": t.get("token_name") or t.get("name") or t.get("note"),
                "expires_at": exp_dt.isoformat(),
                "days_left": days_left,
                "severity": severity,
                "last_used_at": t.get("token_last_used_at"),
                "created_at": t.get("access_granted_at") or t.get("created_at"),
                # repositories_url is provided; counting repos would require extra calls, so omit count here
                "repositories_count": None,
                "permissions": sorted(list((t.get("permissions") or {}).get("organization", {}).keys()) +
                                    list((t.get("permissions") or {}).get("repository", {}).keys())) or None,
            })

    # logs
    if findings:
        LOG.warning("Found %d token(s) expiring within %d day(s).", len(findings), args.days)
        for f in sorted(findings, key=lambda x: (x["severity"] != "CRITICAL", x["days_left"])):
            LOG.warning(
                "SEV=%s owner=%s note=%s expires=%s days_left=%s repos=%s perms=%s last_used=%s id=%s",
                f.get("severity"),
                f.get("owner"),
                f.get("note"),
                f.get("expires_at"),
                f.get("days_left"),
                f.get("repositories_count"),
                ",".join(f.get("permissions") or []),
                f.get("last_used_at"),
                f.get("id"),
            )
    else:
        LOG.info("No tokens expiring within %d day(s).", args.days)

    # outputs
    def _ensure_parent_dir(path: Optional[str]) -> None:
        if path:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)

    _ensure_parent_dir(args.json)
    _ensure_parent_dir(args.md)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "org": org,
                    "window_days": args.days,
                    "warn_threshold": args.warn_threshold,
                    "generated_at": now.isoformat(),
                    "findings": findings,
                },
                fh,
                indent=2,
            )

    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(findings, org, args.days, args.warn_threshold))

    # Slack (optional)
    if slack:
        if findings:
            lines = [
                "*Fine-grained PATs nearing expiry*",
                f"*Org:* `{org}`  •  *Window:* {args.days} day(s)  •  *Warn if ≤* `{args.warn_threshold}` day(s)",
                "",
            ]
            for f in sorted(findings, key=lambda x: (x["severity"] != "CRITICAL", x["days_left"])):
                badge = "🚨" if f["severity"] == "CRITICAL" else "⚠️"
                perms = ", ".join(f.get("permissions") or []) or "—"
                lines.append(
                    f"{badge} `{f.get('owner') or 'unknown'}` — *{f.get('note') or 'unnamed'}* "
                    f"expires `{f['expires_at']}` (*{f['days_left']}d left*; perms: {perms})"
                )
            slack_post(slack, "\n".join(lines))
        else:
            slack_post(slack, f"`{org}`: No PATs expiring within {args.days} day(s).")

    if findings and args.fail_on_findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
