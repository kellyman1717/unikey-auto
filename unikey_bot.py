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

# Sources ranked by measured yield against https://www.getunikey.ai (probe run 2026-09-13).
#   monosans/all.txt  8/30  (27%)  <- best, scheme already prefixed, includes socks
#   roosterkid SOCKS5 3/8   (37%)  <- small list, fresh (hourly commits)
#   roosterkid SOCKS4 3/15  (20%)
#   proxifly http+socks5 4/30 (13%, but flaky - 3 of 4 died on immediate retest)
#   proxyscrape v4     3/30  (10%) <- real API, rate limits -> longest cooldown
#   speedx http        1/90  (1%)  <- filler only
#   shiftytr           0/71  (0%)  <- REMOVED: repo last committed 2023-08-11, all dead
PROXY_SOURCES: list[dict] = [
    {"name": "monosans", "scheme": None, "cooldown": 60,
     "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"},
    {"name": "roosterkid-socks5", "scheme": "socks5", "cooldown": 60,
     "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"},
    {"name": "roosterkid-socks4", "scheme": "socks4", "cooldown": 60,
     "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt"},
    {"name": "proxifly-http", "scheme": "http", "cooldown": 60,
     "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"},
    {"name": "proxifly-socks5", "scheme": "socks5", "cooldown": 60,
     "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"},
    {"name": "proxyscrape-v4", "scheme": None, "cooldown": 120,
     "url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies"
            "&protocol=all&proxy_format=protocolipport&format=text&timeout=20000"},
    {"name": "speedx-http", "scheme": "http", "cooldown": 60,
     "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"},
]

# A bare "IP:PORT" line, possibly surrounded by junk (roosterkid lines look like
# "🇮🇩 203.174.15.138:8080 65ms ID [PT Orion Cyber Internet]"), so this is a
# SEARCH, not a line-anchored match.
IPPORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d{2,5})")

# headers on scrape requests, otherwise public APIs 403 the default python-requests UA
SCRAPE_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# how long a proxy stays banned, by why it died (seconds)
BAN_TTL = {
    "proxy_error": 900,    # tunnel refused / connect timeout -> genuinely dead
    "ssl_error": 900,
    "timeout": 300,        # read timeout -> may be transient target load
    "http_status": 1800,   # 403/429/captive portal -> shared IP already flagged
    "failed_use": 900,     # worked in validation, died during real use
}


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


class ProxyUnavailable(RuntimeError):
    """Raised when no validated proxy can be obtained. Never falls back to direct."""


class ProxyFailure(RuntimeError):
    """A request died because of the proxy (not the target). Triggers rotation."""

    def __init__(self, message: str, reason: str = "proxy_error"):
        super().__init__(message)
        self.reason = reason


class RateLimited(RuntimeError):
    """The target kept answering 429/5xx. The proxy may be fine - don't ban it."""


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", flush=True)


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
#  PROXY
# --------------------------------------------------------------------------
def normalize_proxy(raw: str, default_scheme: str | None = None) -> str | None:
    """Turn any source line into a scheme://ip:port string.

    Handles all three observed formats:
      - 'http://1.2.3.4:8080'          (monosans all.txt, proxifly, proxyscrape)
      - '1.2.3.4:8080'                (speedx, shiftytr)
      - '🇮🇩 1.2.3.4:8080 65ms ID [ISP]'  (roosterkid - decorated, needs a SEARCH)
    The scheme must come from the SOURCE, never be guessed: a socks port
    mislabeled http:// fails in confusing ways much later.
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    m = IPPORT_RE.search(line)
    if not m:
        return None
    ip, port = m.group(1), m.group(2)
    # reject obviously bogus octets / ports
    if not (1 <= int(port) <= 65535):
        return None
    if any(int(o) > 255 for o in ip.split(".")):
        return None

    explicit = re.match(r"^(https?|socks4a?|socks5h?)://", line, re.I)
    if explicit:
        scheme = explicit.group(1).lower()
    else:
        scheme = default_scheme or "http"

    # socks5h forces DNS resolution at the proxy (remote DNS). Without it urllib3
    # resolves locally, which both leaks the hostname and can fail where a
    # remote-resolving handshake would succeed.
    if scheme == "socks5":
        scheme = "socks5h"
    return f"{scheme}://{ip}:{port}"


def fetch_source(src: dict, timeout: float = 15.0) -> list[str]:
    """Fetch and parse one proxy source. Returns [] on any failure."""
    try:
        r = requests.get(src["url"], headers=SCRAPE_HEADERS, timeout=timeout)
        if r.status_code != 200:
            log(f"  source {src['name']}: HTTP {r.status_code}")
            return []
        r.encoding = "utf-8"  # roosterkid SOCKS4.txt is mis-encoded; never let it guess
        out = []
        for line in r.text.splitlines():
            p = normalize_proxy(line, src["scheme"])
            if p:
                out.append(p)
        return out
    except Exception as e:
        log(f"  source {src['name']}: {type(e).__name__}")
        return []


def scrape_proxies(sources: list[dict] | None = None,
                   cache=None) -> list[str]:
    """Pull raw candidates from every source that isn't in cooldown."""
    sources = sources or PROXY_SOURCES
    now = time.monotonic()
    out: list[str] = []

    for src in sources:
        if cache is not None and now < cache.source_cooldown_until(src["name"]):
            continue
        got = fetch_source(src)
        if cache is not None:
            cache.mark_source_fetched(src["name"], src["cooldown"], ok=bool(got))
        log(f"  source {src['name']}: {len(got)} proxies")
        out.extend(got)

    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _classify_failure(exc: BaseException) -> str:
    name = type(exc).__name__
    if "SSLError" in name:
        return "ssl_error"
    if "ProxyError" in name or "ConnectTimeout" in name or "ConnectionError" in name:
        return "proxy_error"
    return "timeout"


def check_proxy(proxy: str, target: str, timeout: tuple[float, float]) -> tuple[bool, float, str]:
    """Validate one proxy. Returns (ok, latency_seconds, ban_reason).

    Strict: only a real 200 with a plausible body counts. A proxy answering
    403/429/captive-portal is NOT usable - it would burn the whole retry
    budget on 429s before being rotated.
    """
    t0 = time.perf_counter()
    try:
        r = requests.get(
            target,
            # BOTH keys must be set: an https:// target with only 'http' set
            # bypasses the proxy entirely.
            proxies={"http": proxy, "https": proxy},
            timeout=timeout,
            headers={"User-Agent": UA, "Accept": "application/json, text/plain, */*"},
            params={"_": random.random()},
        )
        if r.status_code != 200:
            return False, time.perf_counter() - t0, "http_status"
        # body sanity: /api/status returns JSON with a "success" key
        try:
            if r.json().get("success") is not True:
                return False, time.perf_counter() - t0, "http_status"
        except ValueError:
            return False, time.perf_counter() - t0, "http_status"
        return True, time.perf_counter() - t0, ""
    except Exception as e:
        return False, time.perf_counter() - t0, _classify_failure(e)


class ProxyCache:
    """Per-process bans and source cooldowns so we stop re-testing dead proxies."""

    def __init__(self):
        self.banned: dict[str, float] = {}          # proxy -> monotonic expiry
        self.source_until: dict[str, float] = {}    # source name -> monotonic expiry
        self.lock = threading.Lock()

    def is_banned(self, proxy: str) -> bool:
        with self.lock:
            return time.monotonic() < self.banned.get(proxy, 0.0)

    def ban(self, proxy: str, reason: str = "proxy_error") -> None:
        ttl = BAN_TTL.get(reason, 900)
        with self.lock:
            self.banned[proxy] = time.monotonic() + ttl

    def source_cooldown_until(self, name: str) -> float:
        with self.lock:
            return self.source_until.get(name, 0.0)

    def mark_source_fetched(self, name: str, cooldown: float, ok: bool = True) -> None:
        # failed fetches back off harder so a 429'ing API isn't hammered
        with self.lock:
            self.source_until[name] = time.monotonic() + (cooldown if ok else cooldown * 3)


class ProxyPool:
    """Always-on proxy pool.

    Guarantees: take() either returns a validated proxy or raises
    ProxyUnavailable. It never returns None, so no caller can accidentally
    run direct.
    """

    def __init__(self, cfg: dict, cache: ProxyCache | None = None):
        self.cfg = cfg
        self.fixed = cfg.get("proxy")
        self.cache = cache or ProxyCache()
        self.target = cfg["base_url"].rstrip("/") + "/api/status"
        self.want = int(cfg.get("min_pool", 12))
        self.min_pool = int(cfg.get("refill_below", 4))
        self.workers = int(cfg.get("validate_workers", 48))
        self.validate_timeout = float(cfg.get("validate_timeout", 8.0))
        self.pool: list[tuple[str, float]] = []     # (proxy, latency) sorted fastest-first
        self.in_use: set[str] = set()
        self.recent: list[str] = []                 # recently handed out, avoid reusing
        self.lock = threading.Lock()
        self.last_warm = 0.0
        self.warm_interval = float(cfg.get("source_min_interval", 60))

    # -- internal ----------------------------------------------------------
    def _timeout_for(self, proxy: str) -> tuple[float, float]:
        # socks handshakes are slower than a plain HTTP CONNECT
        connect = 8.0 if proxy.startswith("socks") else 5.0
        return (connect, self.validate_timeout)

    def _refill(self, blocking: bool) -> None:
        """Scrape + validate until the pool holds `want` proxies (or we give up)."""
        with self.lock:
            if time.monotonic() - self.last_warm < self.warm_interval and self.pool:
                return
            self.last_warm = time.monotonic()

        rounds = int(self.cfg.get("refill_rounds", 4))
        for rnd in range(1, rounds + 1):
            with self.lock:
                have = len(self.pool)
            need = self.want - have
            if need <= 0:
                return

            raw = scrape_proxies(cache=self.cache)
            if not raw:
                log(f"  refill round {rnd}: no candidates fetched")
            else:
                # spread-sample, never the head (head-of-list is always stale)
                with self.lock:
                    known = {p for p, _ in self.pool}
                cands = [p for p in raw
                         if p not in known and not self.cache.is_banned(p)]
                random.shuffle(cands)
                cands = cands[:int(self.cfg.get("validate_batch", 260))]
                log(f"  refill round {rnd}: validating {len(cands)} candidates "
                    f"(have {have}/{self.want})")

                found = self._validate_batch(cands, need)
                with self.lock:
                    for p, lat in found:
                        if p not in known:
                            self.pool.append((p, lat))
                            known.add(p)
                    self.pool.sort(key=lambda t: t[1])
                    have = len(self.pool)
                log(f"  refill round {rnd}: +{len(found)} -> pool {have}")

            if have >= self.want:
                return
            if rnd < rounds:
                time.sleep(float(self.cfg.get("refill_backoff", 3)))

        with self.lock:
            have = len(self.pool)
        if have == 0:
            raise ProxyUnavailable(
                f"could not obtain any working proxy after {rounds} refill rounds")
        log(f"  WARNING: pool only reached {have}/{self.want}")

    def _validate_batch(self, cands: list[str], want: int) -> list[tuple[str, float]]:
        """Validate concurrently with early exit once `want` good ones are found."""
        if not cands:
            return []
        good: list[tuple[str, float]] = []
        ex = ThreadPoolExecutor(max_workers=min(self.workers, len(cands)))
        try:
            futs = {ex.submit(check_proxy, p, self.target,
                              self._timeout_for(p)): p for p in cands}
            for fut in as_completed(futs):
                p = futs[fut]
                try:
                    ok, lat, reason = fut.result()
                except Exception as e:
                    ok, lat, reason = False, 0.0, _classify_failure(e)
                if ok:
                    good.append((p, lat))
                    if len(good) >= want:
                        break
                else:
                    self.cache.ban(p, reason)
            # stop the stragglers - this is what turns a 60s refill into ~5s
            ex.shutdown(wait=False, cancel_futures=True)
        except Exception:
            ex.shutdown(wait=False, cancel_futures=True)
        return good

    # -- public ------------------------------------------------------------
    def warm(self, blocking: bool = True) -> None:
        """Fill the pool before the first account. Raises if it can't."""
        if self.fixed:
            log(f"using fixed proxy: {self.fixed}")
            return
        log("warming proxy pool ...")
        self._refill(blocking=blocking)
        with self.lock:
            log(f"proxy pool ready: {len(self.pool)} live proxies")

    def take(self) -> str:
        """Return a validated proxy, or raise ProxyUnavailable. Never None."""
        if self.fixed:
            return self.fixed

        # top up before we get to zero, not after
        if len(self._snapshot()) < self.min_pool:
            self._refill(blocking=True)

        with self.lock:
            # prefer the fastest quartile, skipping anything currently in use
            avail = [(p, l) for p, l in self.pool if p not in self.in_use]
            if not avail:
                avail = list(self.pool)
            if not avail:
                raise ProxyUnavailable("pool empty after refill")
            top = avail[:max(1, len(avail) // 4)]

            # avoid handing the same IP to consecutive accounts - reusing one
            # too soon is what trips per-IP rate limits
            fresh = [(p, l) for p, l in top if p not in self.recent]
            pick_from = fresh or top

            proxy, _ = random.choice(pick_from)
            self.in_use.add(proxy)
            self.recent.append(proxy)
            keep = max(1, min(len(self.pool) - 1, int(self.cfg.get("recent_avoid", 5))))
            while len(self.recent) > keep:
                self.recent.pop(0)
            return proxy

    def _snapshot(self) -> list[str]:
        with self.lock:
            return [p for p, _ in self.pool]

    def release(self, proxy: str | None) -> None:
        """Mark a proxy idle again. Safe to call with None or an unknown proxy."""
        if not proxy:
            return
        with self.lock:
            self.in_use.discard(proxy)

    def drop(self, proxy: str | None, reason: str = "failed_use") -> None:
        """Remove a proxy from the pool and ban it. Always logs."""
        if not proxy:
            return
        with self.lock:
            before = len(self.pool)
            self.pool = [(p, l) for p, l in self.pool if p != proxy]
            self.in_use.discard(proxy)
            after = len(self.pool)
        self.cache.ban(proxy, reason)
        if before != after or reason == "failed_use":
            log(f"dropped proxy {proxy} ({reason}) -> {after} left")

    def stats(self) -> str:
        with self.lock:
            return f"{len(self.pool)} live / {len(self.in_use)} in use"


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
                reason = _classify_failure(e)
                raise ProxyFailure(f"{type(e).__name__}: {e}", reason) from e

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


def attempt_with_rotation(cfg: dict, pool: ProxyPool, work) -> tuple[Any, str]:
    """Run `work(client)` rotating proxies on failure.

    `work` raises ProxyFailure  -> ban that proxy, try another (it's the proxy's fault)
             raises RateLimited -> the proxy is fine, the target is throttling;
                                   keep the proxy but still try a fresh IP
             anything else      -> a real error in our own code. Retry on a fresh
                                   proxy (the failure may be data-dependent), but
                                   NEVER blame the proxy for it.

    Returns (result, proxy_used). Raises ProxyUnavailable if we run out.
    """
    attempts = int(cfg.get("proxy_attempts", 5))
    last_exc: BaseException | None = None

    for attempt in range(1, attempts + 1):
        proxy = None
        try:
            proxy = pool.take()
            log(f"using proxy: {proxy}  [{pool.stats()}]")
            result = work(UnikeyClient(cfg, proxy))
            pool.release(proxy)
            return result, proxy
        except ProxyFailure as e:
            # the proxy itself is broken -> ban it and rotate
            log(f"  ! proxy failed ({e.reason}): {str(e)[:120]}")
            pool.drop(proxy, e.reason)
            last_exc = e
        except RateLimited as e:
            # target-side throttle, not the proxy's fault: keep the proxy in the
            # pool, just come back on a different IP
            log(f"  ! rate limited: {str(e)[:120]}")
            pool.release(proxy)
            last_exc = e
        except ProxyUnavailable:
            raise
        except Exception as e:
            # A bug or a bad response shape is NOT the proxy's fault. Dropping
            # the proxy here would burn the whole pool on one code error.
            log(f"  ! error: {type(e).__name__}: {str(e)[:160]}")
            pool.release(proxy)
            last_exc = e
        finally:
            # never let in_use leak, whatever happened above
            if proxy:
                pool.release(proxy)

        if attempt < attempts:
            time.sleep(float(cfg.get("retry_base_delay", 5)))

    raise ProxyUnavailable(
        f"gave up after {attempts} proxy attempts (last: {last_exc})")


def cmd_create(cfg: dict, count: int) -> None:
    acct_path = os.path.join(BASE_DIR, cfg["accounts_file"])
    pool = ProxyPool(cfg)
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
            _, proxy = attempt_with_rotation(
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

    pool = ProxyPool(cfg)
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
            res, proxy = attempt_with_rotation(cfg, pool, work)
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
    pool = ProxyPool(cfg)
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
