#!/usr/bin/env python3
from __future__ import annotations
import os, sys, time, json, logging
from argparse import ArgumentParser
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import jwt  # pyjwt
import requests
from dateutil.parser import isoparse

GITHUB_API = "https://api.github.com"

# ---------- logging: structured & human-friendly ----------
LOG = logging.getLogger("org-pat-audit")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
LOG.setLevel(logging.INFO)
LOG.addHandler(_handler)

def getenv_strict(name: str) -> str:
    val = os.getenv(name)
    if not val:
        LOG.error("Missing required environment variable: %s", name)
        sys.exit(2)
    return val

def gh_app_jwt(app_id: str, pem: str) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}
    return jwt.encode(payload, pem, algorithm="RS256")

def gh_installation_token(jwt_bearer: str, org_name: str, install_id: Optional[str]) -> str:
    headers = {"Authorization": f"Bearer {jwt_bearer}", "Accept": "application/vnd.github+json"}

    if not install_id:
        # Discover installation for this org
        url = f"{GITHUB_API}/app/installations"
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        installs = r.json() or []
        for inst in installs:
            acct = inst.get("account") or {}
            if (acct.get("login") or "").lower() == org_name.lower():
                install_id = str(inst.get("id"))
                break
        if not install_id:
            LOG.error("Could not find installation for org '%s'. Verify the App is installed.", org_name)
            sys.exit(3)

    r = requests.post(
        f"{GITHUB_API}/app/installations/{install_id}/access_tokens",
        headers=headers, timeout=30
    )
    r.raise_for_status()
    tok = r.json().get("token")
    if not tok:
        LOG.error("Installation token response missing 'token'")
        sys.exit(4)
    return tok

def paged_get(url: str, headers: Dict[str, str]) -> List[Any]:
    """Generic paginator for endpoints returning lists; follows 'next' via Link header."""
    items, page = [], 1
    while True:
        u = url if "page=" in url else (url + ("&" if "?" in url else "?") + f"page={page}&per_page=100")
        r = requests.get(u, headers=headers, timeout=30)
        if r.status_code == 404 and page == 1:
            return []  # endpoint not present
        r.raise_for_status()
        batch = r.json()
        if not isinstance(batch, list) or not batch:
            break
        items.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return items

def list_org_fg_pats(org: str, inst_token: str) -> List[Dict[str, Any]]:
    """
    Returns metadata for **approved fine-grained PATs** for the org.
    The exact path name has changed historically; try known variants gracefully.
    """
    headers = {"Authorization": f"token {inst_token}", "Accept": "application/vnd.github+json"}

    candidates = [
        f"{GITHUB_API}/orgs/{org}/personal-access-tokens?state=approved",
        f"{GITHUB_API}/orgs/{org}/fine_grained_personal_access_tokens?state=approved",
    ]
    for base in candidates:
        items = paged_get(base, headers)
        if items:
            return items
    return []

def render_markdown(findings: List[Dict[str, Any]], org: str, window_days: int) -> str:
    if not findings:
        return f"# PAT Expiry Report\n\n**Org:** `{org}`  \n**Window:** {window_days} day(s)\n\nNo tokens expiring within the window.\n"
    lines = [
        f"# PAT Expiry Report",
        f"**Org:** `{org}`  ",
        f"**Window:** {window_days} day(s)",
        "",
        "| Owner | Note | Expires | Last Used | Repos | Permissions | Token ID |",
        "|------:|:-----|:--------|:---------|------:|:------------|:--------:|",
    ]
    for f in findings:
        perms = ", ".join(f.get("permissions") or []) or "—"
        lines.append(
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

def main() -> None:
    ap = ArgumentParser(description="Audit org fine-grained PAT expirations (via GitHub App)")
    ap.add_argument("--days", type=int, default=30, help="Alert window in days (default: 30)")
    ap.add_argument("--json", type=str, help="Write full JSON findings to this path")
    ap.add_argument("--md", type=str, help="Write Markdown report to this path")
    ap.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if anything is expiring within the window")
    args = ap.parse_args()

    # strict env
    app_id  = getenv_strict("GH_APP_ID")
    pem     = getenv_strict("GH_APP_PRIVATE_KEY")
    org     = getenv_strict("ORG_NAME")
    inst_id = os.getenv("GH_APP_INSTALLATION_ID")
    slack   = os.getenv("SLACK_WEBHOOK_URL")

    jwt_bearer = gh_app_jwt(app_id, pem)
    inst_token = gh_installation_token(jwt_bearer, org, inst_id)

    tokens = list_org_fg_pats(org, inst_token)
    if not isinstance(tokens, list):
        LOG.error("Unexpected API response shape (expected list).")
        sys.exit(5)

    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=args.days)

    findings: List[Dict[str, Any]] = []
    for t in tokens:
        exp = t.get("expires_at")
        if not exp:
            continue
        try:
            exp_dt = isoparse(exp)
        except Exception:
            continue
        if exp_dt <= horizon:
            findings.append({
                "id": t.get("id"),
                "owner": (t.get("owner") or {}).get("login") or t.get("owner_login"),
                "note": t.get("name") or t.get("note"),
                "expires_at": exp_dt.isoformat(),
                "last_used_at": t.get("last_used_at"),
                "created_at": t.get("created_at"),
                "repositories_count": len(t.get("repositories") or []),
                "permissions": sorted(list((t.get("permissions") or {}).keys())),
            })

    # logs
    if findings:
        LOG.warning("Found %d token(s) expiring within %d day(s).", len(findings), args.days)
        for f in findings:
            LOG.warning(
                "owner=%s note=%s expires=%s repos=%s perms=%s last_used=%s id=%s",
                f.get("owner"), f.get("note"), f.get("expires_at"),
                f.get("repositories_count"), ",".join(f.get("permissions") or []),
                f.get("last_used_at"), f.get("id")
            )
    else:
        LOG.info("No tokens expiring within %d day(s).", args.days)

    # outputs
    os.makedirs("out", exist_ok=True)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"org": org, "window_days": args.days, "generated_at": now.isoformat(), "findings": findings}, fh, indent=2)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(findings, org, args.days))

    if slack:
        if findings:
            lines = [
                "*Fine-grained PATs nearing expiry*",
                f"*Org:* `{org}`  •  *Window:* {args.days} day(s)",
                "",
            ]
            for f in findings:
                perms = ", ".join(f.get("permissions") or []) or "—"
                lines.append(f"• `{f.get('owner') or 'unknown'}` — *{f.get('note') or 'unnamed'}* expires `{f['expires_at']}` (perms: {perms})")
            slack_post(slack, "\n".join(lines))
        else:
            slack_post(slack, f"`{org}`: No PATs expiring within {args.days} day(s).")

    if findings and args.fail_on_findings:
        sys.exit(1)

if __name__ == "__main__":
    main()
