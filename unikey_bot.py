"""
UNIKEY auto-registration bot.

Flow (pure HTTP, no browser):
  1. scrape free proxy (ProxyScrape) -- optional, dev only
  2. generate a fresh EVM wallet (auto-create wallet)
  3. solve Cloudflare Turnstile via Boterdrop-Solver  (http://127.0.0.1:8000)
  4. POST /api/oauth/web3/challenge  -> nonce + message
  5. sign message with wallet key (personal_sign / EIP-191)
  6. POST /api/oauth/web3/verify     -> session cookie (auto sign-up)
  7. create API key + reveal key
  8. read / refresh credits

Usage:
  python unikey_bot.py create [count]     create N accounts (default 1)
  python unikey_bot.py refresh            refresh quota for all saved accounts
  python unikey_bot.py list               print saved accounts
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import random
import threading
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from eth_account import Account
from eth_account.messages import encode_defunct

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

# Logika proxy ada di modul terpisah supaya bisa dipakai skrip lain.
from proxypool import (                                    # noqa: E402
    ProxyPool, ProxyUnavailable, ProxyFailure, RateLimited,
    attempt_with_rotation, classify_failure,
)


_SOLVER_SESSION: requests.Session | None = None


def solver_session() -> requests.Session:
    """Reusable session for the localhost Turnstile solver.

    trust_env=False so an env/registry proxy can't break 127.0.0.1 calls.
    """
    global _SOLVER_SESSION
    if _SOLVER_SESSION is None:
        s = requests.Session()
        s.trust_env = False
        s.headers.update({"User-Agent": UA, "Accept": "application/json"})
        _SOLVER_SESSION = s
    return _SOLVER_SESSION


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", flush=True)


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)



# --------------------------------------------------------------------------
#  HTTP CLIENT
# --------------------------------------------------------------------------
class UnikeyClient:
    """HTTP client that is ALWAYS routed through a proxy."""

    def __init__(self, cfg: dict, proxy: str):
        if not proxy:
            # no silent direct mode - an unproxied request would leak the real IP
            raise ProxyUnavailable("UnikeyClient requires a proxy, got none")
        self.cfg = cfg
        self.base = cfg["base_url"].rstrip("/")
        self.proxy = proxy
        self.session = requests.Session()
        retry = Retry(total=0)  # we rotate proxies instead of retrying one
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": self.base,
        })
        # Without this, an HTTP_PROXY env var or a Windows IE/registry proxy
        # silently overrides session.proxies (verified). Same for no_proxy.
        self.session.trust_env = False
        # both keys, or an https:// target bypasses the proxy entirely
        self.proxy_dict = {"http": proxy, "https": proxy}
        self.uid: int | None = None

    # -- low level ---------------------------------------------------------
    def request(self, method: str, path: str, *, json_body: Any = None,
                params: dict | None = None, referer: str | None = None,
                headers: dict | None = None, retry_on_rate_limit: bool = True):
        url = self.base + path
        hdr = dict(headers or {})
        hdr.setdefault("Referer", referer or (self.base + "/sign-in"))
        if json_body is not None:
            hdr.setdefault("Content-Type", "application/json")
        if self.uid is not None:
            hdr.setdefault("New-Api-User", str(self.uid))

        timeout = self.cfg.get("request_timeout", 30)
        # with a proxy in play, retrying the same dead IP is wasted time
        max_retries = int(self.cfg.get("max_retries", 3))
        base_delay = self.cfg.get("retry_base_delay", 5)

        last = None
        for attempt in range(1, max_retries + 1):
            try:
                r = self.session.request(method, url, json=json_body, params=params,
                                         headers=hdr, timeout=timeout,
                                         proxies=self.proxy_dict)
            except requests.RequestException as e:
                # distinguish a dead proxy from server trouble: only a proxy
                # fault should trigger rotation upstream
                raise ProxyFailure(f"{type(e).__name__}: {e}",
                                   classify_failure(e)) from e

            if r.status_code == 429 or (r.status_code >= 500 and retry_on_rate_limit):
                last = f"HTTP {r.status_code}"
                if attempt == max_retries:
                    break
                log(f"  ! {last} {r.text[:80]} -> retry {attempt}/{max_retries}")
                time.sleep(base_delay * attempt + random.uniform(0, 2))
                continue
            return r
        raise RateLimited(f"rate limited after {max_retries} tries: {method} {path} ({last})")

    def jrequest(self, method: str, path: str, **kw) -> dict:
        r = self.request(method, path, **kw)
        try:
            return r.json()
        except ValueError:
            raise RuntimeError(f"non-JSON response ({r.status_code}): {r.text[:200]}")

    # -- steps -------------------------------------------------------------
    def fetch_status(self) -> dict:
        return self.jrequest("GET", "/api/status")["data"]

    def turnstile_token(self) -> str | None:
        """Ask Boterdrop-Solver for a Turnstile token."""
        status = self.fetch_status()
        if not status.get("turnstile_check"):
            return None
        sitekey = status["turnstile_site_key"]
        solver = self.cfg["solver_url"].rstrip("/")
        page = self.cfg.get("turnstile_page_url") or (self.base + "/sign-in")

        # the solver is a localhost service - never route it through a proxy
        r = solver_session().get(solver + "/turnstile",
                                 params={"url": page, "sitekey": sitekey}, timeout=30)
        r.raise_for_status()
        task_id = r.json().get("task_id")
        if not task_id:
            raise RuntimeError(f"solver returned no task_id: {r.text[:200]}")

        deadline = time.time() + self.cfg.get("turnstile_timeout", 120)
        while time.time() < deadline:
            rr = solver_session().get(solver + "/result", params={"id": task_id}, timeout=30)
            j = rr.json()
            st = j.get("status")
            if st == "success":
                return j["value"]
            if st not in ("process", "accepted"):
                raise RuntimeError(f"solver failed: {str(j)[:200]}")
            time.sleep(0.5)
        raise RuntimeError("turnstile solve timeout")

    def signup_with_wallet(self, account, chain_id: int = 56) -> dict:
        """Auto sign-up/login using a generated wallet. Returns verify payload."""
        addr = account.address
        token = self.turnstile_token()

        ch = self.jrequest("POST", "/api/oauth/web3/challenge",
                           json_body={"wallet_address": addr})["data"]
        message = ch["message"]
        sig = Account.sign_message(encode_defunct(text=message),
                                   account.key).signature.hex()

        body = {
            "action": "login",
            "wallet_address": addr,
            "nonce": ch["nonce"],
            "signature": sig,
            "chain_id": chain_id,
            "turnstile": token or "",
            "hcaptcha": "",
        }
        res = self.jrequest("POST", "/api/oauth/web3/verify",
                            json_body=body,
                            params={"turnstile": token or "", "hcaptcha": ""})
        if not res.get("success"):
            raise RuntimeError(f"verify failed: {str(res)[:200]}")
        data = res["data"]
        self.uid = data["id"]
        return data

    def get_self(self) -> dict:
        return self.jrequest("GET", "/api/user/self",
                             referer=self.base + "/dashboard")["data"]

    def create_api_key(self, name: str | None = None) -> dict | None:
        """Create a token then reveal its full key. Returns token row + key."""
        payload = {
            "name": name or self.cfg.get("token_name", "auto"),
            "remain_quota": 0,
            "expired_time": -1,
            "unlimited_quota": bool(self.cfg.get("unlimited_quota", True)),
            "model_limits_enabled": False,
            "model_limits": "",
            "allow_ips": "",
            "group": "",
            "cross_group_retry": False,
        }
        self.jrequest("POST", "/api/token/", json_body=payload,
                      referer=self.base + "/console/token")

        lst = self.jrequest("GET", "/api/token/?p=1&size=20",
                            referer=self.base + "/console/token")["data"]
        items = lst.get("items") or []
        if not items:
            return None
        row = max(items, key=lambda t: t["id"])
        key = self.jrequest("POST", f"/api/token/{row['id']}/key",
                            referer=self.base + "/console/token").get("data", {}).get("key")
        return {"id": row["id"], "name": row.get("name"), "key": key,
                "created_time": row.get("created_time")}

    def get_credits(self) -> dict:
        """Fetch current credit/quota info (fresh from server)."""
        me = self.get_self()
        quota = me.get("quota", 0)
        used = me.get("used_quota", 0)
        gift = me.get("gift_quota", 0)
        return {
            "user_id": me.get("id"),
            "username": me.get("username"),
            "wallet_address": me.get("wallet_address"),
            "display_name": me.get("display_name"),
            "group": me.get("group"),
            "aff_code": me.get("aff_code"),
            "quota": quota,
            "used_quota": used,
            "gift_quota": gift,
            "transferable_quota": me.get("transferable_quota", 0),
            "aff_quota": me.get("aff_quota", 0),
            "request_count": me.get("request_count", 0),
            "remaining": quota - used,
            "checked_at": int(time.time()),
        }

    def check_api_key_works(self, key: str) -> bool:
        """Sanity-check the created API key against the OpenAI-compatible endpoint.

        The /api/* surface is session-cookie based (it answers "Unauthorized,
        invalid access token" for a valid key), so the gateway endpoint is the
        right probe: it must answer 200 with models AND reject an empty key.
        """
        try:
            hdr = {"Authorization": "Bearer " + key, "User-Agent": UA,
                   "Accept": "application/json"}
            kw = {"timeout": self.cfg.get("request_timeout", 30),
                  "proxies": self.proxy_dict}
            r = requests.get(self.base + "/v1/models", headers=hdr, **kw)
            if r.status_code != 200 or not (r.json().get("data") or []):
                return False
            # make sure the endpoint isn't just open to everyone
            r2 = requests.get(self.base + "/v1/models",
                              headers={"Authorization": "Bearer invalid",
                                       "User-Agent": UA}, **kw)
            return r2.status_code != 200
        except Exception:
            return False


# --------------------------------------------------------------------------
#  STORAGE
# --------------------------------------------------------------------------
def load_accounts(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_accounts(path: str, accounts: list[dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def upsert_account(path: str, rec: dict) -> list[dict]:
    accounts = load_accounts(path)
    for i, a in enumerate(accounts):
        if a.get("user_id") == rec.get("user_id") or \
           (a.get("address") or "").lower() == (rec.get("address") or "").lower():
            accounts[i] = {**a, **rec}
            save_accounts(path, accounts)
            return accounts
    accounts.append(rec)
    save_accounts(path, accounts)
    return accounts


def write_hasil(path: str, accounts: list[dict]) -> None:
    """Write a plain-text summary: just the account + API key.

    Full data (private key, proxy, credit history) stays in accounts.json,
    which is referenced at the top of the file.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ok = [a for a in accounts if a.get("api_key")]

    lines = [
        "=" * 60,
        "UNIKEY AUTO - DAFTAR AKUN",
        f"Update: {now}",
        "=" * 60,
        "",
        "File ini hanya berisi ringkasan: akun dan API key.",
        "Untuk detail lengkap (private key, proxy, riwayat kredit)",
        "buka file: accounts.json",
        "",
        f"Total akun: {len(ok)}",
        "",
    ]

    for i, a in enumerate(ok, 1):
        c = a.get("credits") or {}
        remaining = c.get("remaining")
        lines += [
            "-" * 60,
            f"[{i}] {a.get('username') or a.get('address')}",
            f"    API Key : {a.get('api_key')}",
            f"    Kredit  : {remaining if remaining is not None else '-'}",
            f"    Status  : {a.get('status', '-')}",
        ]
    lines.append("-" * 60)
    lines.append("")

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp, path)


# --------------------------------------------------------------------------
#  COMMANDS
# --------------------------------------------------------------------------
def run_create_flow(cfg: dict, client: UnikeyClient, acct, record: dict) -> None:
    """One full sign-up attempt on an already-built client."""
    # 1. sign up with the generated wallet
    log("solving turnstile ...")
    info = client.signup_with_wallet(acct, cfg.get("chain_id", 56))
    record["user_id"] = info["id"]
    record["username"] = info.get("username")
    record["display_name"] = info.get("display_name")
    record["group"] = info.get("group")
    log(f"signed up: id={info['id']} user={info.get('username')}")

    # 2. create + reveal api key
    if cfg.get("auto_create_api_key", True):
        tk = client.create_api_key()
        if tk:
            record["api_key_id"] = tk["id"]
            record["api_key"] = tk["key"]
            log(f"api key: {tk['key']}")
            record["api_key_valid"] = client.check_api_key_works(tk["key"])

    # 3. credits
    credits = client.get_credits()
    record["credits"] = credits
    record["last_credit_check"] = credits["checked_at"]
    log(f"credits: {credits['remaining']} (quota={credits['quota']}, "
        f"used={credits['used_quota']}, gift={credits['gift_quota']})")

    record["status"] = "ok"


def run_with_rotation(cfg: dict, pool: ProxyPool, work) -> tuple[Any, str]:
    """Jalankan `work(client)` dengan rotasi proxy.

    Pembungkus tipis di atas proxypool.attempt_with_rotation: modul itu bekerja
    dengan string proxy, sedangkan bot ini butuh UnikeyClient yang sudah terpasang
    proxy. Parameter waktunya diambil dari config.
    """
    return attempt_with_rotation(
        pool,
        lambda proxy: work(UnikeyClient(cfg, proxy)),
        attempts=int(cfg.get("proxy_attempts", 5)),
        retry_delay=float(cfg.get("retry_base_delay", 5)),
        logger=log,
    )


def make_pool(cfg: dict) -> ProxyPool:
    """Bangun ProxyPool dari config.json.

    Target validasinya /api/status milik UNIKEY sendiri, supaya proxy yang lolos
    benar-benar bisa menjangkau server tujuan.
    """
    return ProxyPool(
        target=cfg["base_url"].rstrip("/") + "/api/status",
        fixed=cfg.get("proxy"),
        want=int(cfg.get("min_pool", 12)),
        min_pool=int(cfg.get("refill_below", 4)),
        refill_rounds=int(cfg.get("refill_rounds", 4)),
        refill_backoff=float(cfg.get("refill_backoff", 3)),
        validate_batch=int(cfg.get("validate_batch", 260)),
        validate_workers=int(cfg.get("validate_workers", 48)),
        validate_timeout=float(cfg.get("validate_timeout", 8.0)),
        source_min_interval=float(cfg.get("source_min_interval", 60)),
        recent_avoid=int(cfg.get("recent_avoid", 5)),
        logger=log,
    )


def cmd_create(cfg: dict, count: int) -> None:
    acct_path = os.path.join(BASE_DIR, cfg["accounts_file"])
    pool = make_pool(cfg)
    pool.warm()   # raises ProxyUnavailable if it can't get any proxy

    for i in range(1, count + 1):
        log(f"=== account {i}/{count} ===")
        acct = Account.create()
        record: dict = {
            "index": i,
            "created_at": int(time.time()),
            "address": acct.address,
            "private_key": acct.key.hex(),
        }
        log(f"wallet created: {acct.address}")

        try:
            _, proxy = run_with_rotation(
                cfg, pool, lambda client: run_create_flow(cfg, client, acct, record))
            record["proxy"] = proxy
        except Exception as e:
            log(f"FAILED: {type(e).__name__}: {e}")
            record["status"] = "error"
            record["error"] = f"{type(e).__name__}: {e}"

        accounts = upsert_account(acct_path, record)
        write_hasil(os.path.join(BASE_DIR, cfg.get("hasil_file", "hasil.txt")), accounts)
        log(f"saved -> {cfg['accounts_file']} + {cfg.get('hasil_file', 'hasil.txt')}")

        if i < count:
            d = cfg.get("delay_between_accounts", 3)
            if d:
                time.sleep(d)


def cmd_refresh(cfg: dict) -> None:
    acct_path = os.path.join(BASE_DIR, cfg["accounts_file"])
    accounts = load_accounts(acct_path)
    if not accounts:
        log("no saved accounts")
        return

    pool = make_pool(cfg)
    pool.warm()
    changed = False

    for a in accounts:
        pk = a.get("private_key")
        if not pk:
            log(f"skip {a.get('username') or a.get('address')}: no private key")
            continue
        log(f"refresh {a.get('username') or a.get('address')} ...")

        def work(client: UnikeyClient):
            acct = Account.from_key(pk)
            info = client.signup_with_wallet(acct, cfg.get("chain_id", 56))
            out = {"info": info}
            if not a.get("api_key") and cfg.get("auto_create_api_key", True):
                tk = client.create_api_key()
                if tk:
                    out["token"] = tk
                    tk["valid"] = client.check_api_key_works(tk["key"])
            out["credits"] = client.get_credits()
            return out

        try:
            res, proxy = run_with_rotation(cfg, pool, work)
            info = res["info"]
            a["user_id"] = info["id"]
            a["username"] = info.get("username", a.get("username"))
            a["display_name"] = info.get("display_name", a.get("display_name"))
            if "token" in res:
                a["api_key_id"] = res["token"]["id"]
                a["api_key"] = res["token"]["key"]
                a["api_key_valid"] = res["token"].get("valid")
            a["credits"] = res["credits"]
            a["last_credit_check"] = res["credits"]["checked_at"]
            a["proxy"] = proxy
            a["status"] = "ok"
            c = res["credits"]
            log(f"  -> remaining {c['remaining']} "
                f"(quota={c['quota']}, used={c['used_quota']})")
            changed = True
        except Exception as e:
            log(f"  ! FAILED {type(e).__name__}: {e}")

        time.sleep(cfg.get("delay_between_accounts", 3))

    if changed:
        save_accounts(acct_path, accounts)
        write_hasil(os.path.join(BASE_DIR, cfg.get("hasil_file", "hasil.txt")), accounts)
        log(f"saved -> {cfg['accounts_file']} + {cfg.get('hasil_file', 'hasil.txt')}")


def cmd_proxy(cfg: dict, count: int) -> None:
    """Fetch + validate proxies and print them, without creating any account."""
    pool = make_pool(cfg)
    pool.warm()
    with pool.lock:
        rows = list(pool.pool)
    print(f"\n{len(rows)} live proxies (fastest first):")
    for p, lat in rows:
        print(f"  {lat:6.2f}s  {p}")
    if not rows:
        sys.exit(1)


def cmd_export(cfg: dict) -> None:
    """Rebuild hasil.txt from accounts.json without touching the network."""
    acct_path = os.path.join(BASE_DIR, cfg["accounts_file"])
    accounts = load_accounts(acct_path)
    if not accounts:
        log("no saved accounts")
        return
    out = os.path.join(BASE_DIR, cfg.get("hasil_file", "hasil.txt"))
    write_hasil(out, accounts)
    log(f"{len([a for a in accounts if a.get('api_key')])} akun -> {os.path.basename(out)}")


def cmd_list(cfg: dict) -> None:
    acct_path = os.path.join(BASE_DIR, cfg["accounts_file"])
    accounts = load_accounts(acct_path)
    if not accounts:
        log("no saved accounts")
        return
    for a in accounts:
        c = a.get("credits") or {}
        ts = a.get("last_credit_check")
        when = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"
        print("-" * 70)
        print(f"  user        : {a.get('username')} (id={a.get('user_id')})")
        print(f"  wallet      : {a.get('address')}")
        print(f"  private key : {a.get('private_key')}")
        print(f"  api key     : {a.get('api_key')}")
        print(f"  credits     : {c.get('remaining')} remaining "
              f"(quota={c.get('quota')}, used={c.get('used_quota')}, gift={c.get('gift_quota')})")
        print(f"  updated     : {when}   status={a.get('status')}")


def main() -> None:
    ap = argparse.ArgumentParser(description="UNIKEY auto sign-up bot (full HTTP, always proxied)")
    ap.add_argument("command", choices=["create", "refresh", "list", "proxy", "export"],
                    help="action")
    ap.add_argument("count", nargs="?", type=int, default=1,
                    help="number of accounts to create (create only)")
    args = ap.parse_args()

    cfg = load_config()
    if args.command == "create":
        cmd_create(cfg, max(1, args.count))
    elif args.command == "refresh":
        cmd_refresh(cfg)
    elif args.command == "proxy":
        cmd_proxy(cfg, max(1, args.count))
    elif args.command == "export":
        cmd_export(cfg)
    else:
        cmd_list(cfg)


if __name__ == "__main__":
    main()
