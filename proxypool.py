"""
Pool proxy otomatis untuk requests. Modul mandiri, tidak terikat ke bot mana pun.

Mengambil proxy gratis dari beberapa sumber publik, memvalidasinya, lalu
menyediakannya lewat pool yang selalu terisi. Proxy yang mati dibuang dan
dibanned sementara supaya tidak dites ulang.

Pemakaian dasar:

    from proxypool import ProxyPool

    pool = ProxyPool(target="https://httpbin.org/ip")
    pool.warm()                       # siapkan pool, raise kalau gagal

    proxy = pool.take()               # selalu dapat proxy, tidak pernah None
    try:
        r = requests.get(url, proxies=pool.proxies_for(proxy))
    finally:
        pool.release(proxy)           # kembalikan ke pool

Rotasi otomatis saat gagal:

    from proxypool import attempt_with_rotation

    def kerja(client):
        return client.get(url)

    hasil, proxy = attempt_with_rotation(pool, kerja)

Contoh dengan validator khusus (misal target harus balas JSON tertentu):

    def cek(resp):
        return resp.status_code == 200 and resp.json().get("ok") is True

    pool = ProxyPool(target="https://situs.com/api/status", validator=cek)

PySocks wajib terpasang kalau memakai proxy SOCKS:  pip install "requests[socks]"
"""

from __future__ import annotations

import re
import time
import random
import threading
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

import requests

__all__ = [
    "ProxyPool", "ProxyCache", "ProxyUnavailable", "ProxyFailure", "RateLimited",
    "attempt_with_rotation", "normalize_proxy", "proxied_session",
    "PROXY_SOURCES", "BAN_TTL",
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

# Sumber proxy gratis, diurutkan berdasarkan hasil ukur (2026-09-13).
#   monosans/all.txt  8/30  (27%)  <- terbaik, skema sudah lengkap, ada socks
#   roosterkid SOCKS5 3/8   (37%)  <- kecil tapi segar (commit per jam)
#   roosterkid SOCKS4 3/15  (20%)
#   proxifly http+socks5 4/30 (13%, tapi rapuh - 3 dari 4 mati saat dites ulang)
#   proxyscrape v4     3/30  (10%) <- API asli, kena rate limit, cooldown panjang
#   speedx http        1/90  (1%)  <- cadangan
#   shiftytr           0/71  (0%)  <- DIBUANG: commit terakhir 2023-08-11, mati semua
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

# Baris "IP:PORT" polos, kadang diapit teks lain (baris roosterkid bentuknya
# "🇮🇩 203.174.15.138:8080 65ms ID [PT Orion Cyber Internet]"), jadi ini
# pencarian (search), bukan pencocokan di awal baris.
IPPORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d{2,5})")

# Header saat mengambil daftar proxy, kalau tidak API publik menolak
# User-Agent bawaan python-requests.
SCRAPE_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Berapa lama sebuah proxy dibanned, tergantung penyebab matinya (detik).
BAN_TTL = {
    "proxy_error": 900,    # tunnel ditolak / connect timeout -> benar-benar mati
    "ssl_error": 900,
    "timeout": 300,        # read timeout -> bisa jadi target sedang lambat
    "http_status": 1800,   # 403/429/captive portal -> IP bersama sudah ditandai
    "failed_use": 900,     # lolos validasi, mati saat dipakai sungguhan
}


def _default_log(msg: str) -> None:
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", flush=True)


class ProxyUnavailable(RuntimeError):
    """Tidak ada proxy valid yang bisa didapat. Tidak pernah jatuh ke koneksi langsung."""


class ProxyFailure(RuntimeError):
    """Request gagal karena proxinya (bukan karena target). Memicu rotasi."""

    def __init__(self, message: str, reason: str = "proxy_error"):
        super().__init__(message)
        self.reason = reason


class RateLimited(RuntimeError):
    """Target terus membalas 429/5xx. Proxinya belum tentu buruk - jangan dibanned."""


def proxies_for(proxy: str) -> dict[str, str]:
    """Dict proxies untuk requests. Dua key wajib diisi.

    Kalau hanya 'http' yang diisi, target https:// akan melewati proxy
    sepenuhnya dan koneksi keluar dari IP asli.
    """
    return {"http": proxy, "https": proxy}


def proxied_session(proxy: str | None = None, headers: dict | None = None) -> requests.Session:
    """Session requests yang tidak bisa dibelokkan proxy dari luar.

    trust_env=False penting: tanpa itu, variabel HTTP_PROXY atau proxy dari
    registry Windows bisa diam-diam menggantikan proxy yang kita pasang.
    """
    s = requests.Session()
    s.trust_env = False
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    if headers:
        s.headers.update(headers)
    if proxy:
        s.proxies.update(proxies_for(proxy))
    return s


def normalize_proxy(raw: str, default_scheme: str | None = None) -> str | None:
    """Ubah satu baris sumber menjadi bentuk scheme://ip:port.

    Menangani tiga format yang ada:
      - 'http://1.2.3.4:8080'          (monosans all.txt, proxifly, proxyscrape)
      - '1.2.3.4:8080'                 (speedx)
      - '🇮🇩 1.2.3.4:8080 65ms ID [ISP]'  (roosterkid - berhias, perlu SEARCH)

    Skema harus datang dari sumbernya, tidak boleh dikira-kira: port socks yang
    salah dilabeli http:// akan gagal jauh di belakang dengan pesan yang
    membingungkan.
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    m = IPPORT_RE.search(line)
    if not m:
        return None
    ip, port = m.group(1), m.group(2)
    if not (1 <= int(port) <= 65535):
        return None
    if any(int(o) > 255 for o in ip.split(".")):
        return None

    explicit = re.match(r"^(https?|socks4a?|socks5h?)://", line, re.I)
    if explicit:
        scheme = explicit.group(1).lower()
    else:
        scheme = default_scheme or "http"

    # socks5h memaksa DNS diselesaikan di proxy (remote DNS). Tanpa itu urllib3
    # menyelesaikannya secara lokal: nama host bocor, dan sebagian proxy yang
    # sebenarnya bisa malah gagal.
    if scheme == "socks5":
        scheme = "socks5h"
    return f"{scheme}://{ip}:{port}"


def fetch_source(src: dict, timeout: float = 15.0,
                 logger: Callable[[str], None] = _default_log) -> list[str]:
    """Ambil dan uraikan satu sumber proxy. Mengembalikan [] kalau gagal."""
    try:
        r = requests.get(src["url"], headers=SCRAPE_HEADERS, timeout=timeout)
        if r.status_code != 200:
            logger(f"  source {src['name']}: HTTP {r.status_code}")
            return []
        r.encoding = "utf-8"  # SOCKS4.txt roosterkid salah encoding; jangan ditebak
        out = []
        for line in r.text.splitlines():
            p = normalize_proxy(line, src.get("scheme"))
            if p:
                out.append(p)
        return out
    except Exception as e:
        logger(f"  source {src['name']}: {type(e).__name__}")
        return []


def scrape_proxies(sources: list[dict] | None = None,
                   cache: "ProxyCache | None" = None,
                   logger: Callable[[str], None] = _default_log) -> list[str]:
    """Ambil kandidat dari semua sumber yang tidak sedang cooldown."""
    sources = sources if sources is not None else PROXY_SOURCES
    now = time.monotonic()
    out: list[str] = []

    for src in sources:
        if cache is not None and now < cache.source_cooldown_until(src["name"]):
            continue
        got = fetch_source(src, logger=logger)
        if cache is not None:
            cache.mark_source_fetched(src["name"], src.get("cooldown", 60), ok=bool(got))
        logger(f"  source {src['name']}: {len(got)} proxies")
        out.extend(got)

    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def classify_failure(exc: BaseException) -> str:
    """Petakan exception menjadi alasan ban."""
    name = type(exc).__name__
    if "SSLError" in name:
        return "ssl_error"
    if "ProxyError" in name or "ConnectTimeout" in name or "ConnectionError" in name:
        return "proxy_error"
    return "timeout"


def check_proxy(proxy: str, target: str, timeout: tuple[float, float],
                validator: Callable[[requests.Response], bool] | None = None
                ) -> tuple[bool, float, str]:
    """Validasi satu proxy. Mengembalikan (ok, latency_detik, alasan_ban).

    Ketat secara bawaan: hanya HTTP 200 yang dianggap lolos. Proxy yang membalas
    403/429/captive portal TIDAK layak pakai - dia akan menghabiskan jatah retry
    sebelum akhirnya dirotasi.

    `validator` bisa dipakai kalau target butuh pengecekan isi, misalnya harus
    balas JSON dengan field tertentu.
    """
    t0 = time.perf_counter()
    try:
        r = requests.get(
            target,
            proxies=proxies_for(proxy),
            timeout=timeout,
            headers={"User-Agent": UA, "Accept": "application/json, text/plain, */*"},
            params={"_": random.random()},
        )
        elapsed = time.perf_counter() - t0
        if validator is not None:
            try:
                return (True, elapsed, "") if validator(r) else (False, elapsed, "http_status")
            except Exception:
                return False, elapsed, "http_status"
        if r.status_code != 200:
            return False, elapsed, "http_status"
        return True, elapsed, ""
    except Exception as e:
        return False, time.perf_counter() - t0, classify_failure(e)


class ProxyCache:
    """Ban per-proses dan cooldown sumber, supaya proxy mati tidak dites berulang."""

    def __init__(self, ban_ttl: dict[str, float] | None = None):
        self.ban_ttl = dict(ban_ttl or BAN_TTL)
        self.banned: dict[str, float] = {}          # proxy -> kedaluwarsa (monotonic)
        self.source_until: dict[str, float] = {}    # nama sumber -> kedaluwarsa
        self.lock = threading.Lock()

    def is_banned(self, proxy: str) -> bool:
        with self.lock:
            return time.monotonic() < self.banned.get(proxy, 0.0)

    def ban(self, proxy: str, reason: str = "proxy_error") -> None:
        ttl = self.ban_ttl.get(reason, 900)
        with self.lock:
            self.banned[proxy] = time.monotonic() + ttl

    def source_cooldown_until(self, name: str) -> float:
        with self.lock:
            return self.source_until.get(name, 0.0)

    def mark_source_fetched(self, name: str, cooldown: float, ok: bool = True) -> None:
        # pengambilan yang gagal mundur lebih lama agar API yang kena rate limit
        # tidak terus dihantam
        with self.lock:
            self.source_until[name] = time.monotonic() + (cooldown if ok else cooldown * 3)


class ProxyPool:
    """Pool proxy yang selalu hidup.

    Jaminan: take() mengembalikan proxy yang sudah divalidasi atau melempar
    ProxyUnavailable. Tidak pernah mengembalikan None, jadi pemanggilnya tidak
    mungkin tanpa sengaja konek langsung.

    Parameter:
      target          URL yang dipakai untuk menguji proxy. Pakai endpoint
                      ringan milik situs tujuan supaya yang diuji relevan.
      validator       opsional, fungsi penilai isi response.
      fixed           proxy tetap (mis. dari config). Kalau diisi, pool tidak
                      mengambil dari sumber publik.
      want/min_pool   target jumlah proxy hidup dan ambang pengisian ulang.
      sources         daftar sumber; bawaannya PROXY_SOURCES.
      logger          fungsi log; bawaan cetak dengan timestamp.
    """

    def __init__(
        self,
        target: str,
        *,
        validator: Callable[[requests.Response], bool] | None = None,
        fixed: str | None = None,
        want: int = 12,
        min_pool: int = 4,
        refill_rounds: int = 4,
        refill_backoff: float = 3.0,
        validate_batch: int = 260,
        validate_workers: int = 48,
        validate_timeout: float = 8.0,
        source_min_interval: float = 60.0,
        recent_avoid: int = 5,
        sources: list[dict] | None = None,
        cache: ProxyCache | None = None,
        logger: Callable[[str], None] = _default_log,
    ):
        self.target = target
        self.validator = validator
        self.fixed = fixed
        self.want = int(want)
        self.min_pool = int(min_pool)
        self.refill_rounds = int(refill_rounds)
        self.refill_backoff = float(refill_backoff)
        self.validate_batch = int(validate_batch)
        self.workers = int(validate_workers)
        self.validate_timeout = float(validate_timeout)
        self.warm_interval = float(source_min_interval)
        self.recent_avoid = int(recent_avoid)
        self.sources = sources if sources is not None else PROXY_SOURCES
        self.cache = cache or ProxyCache()
        self.log = logger

        self.pool: list[tuple[str, float]] = []   # (proxy, latency) tercepat dulu
        self.in_use: set[str] = set()
        self.recent: list[str] = []               # yang baru dibagikan, hindari ulang
        self.lock = threading.Lock()
        self.last_warm = 0.0

    # -- internal ----------------------------------------------------------
    def _timeout_for(self, proxy: str) -> tuple[float, float]:
        # handshake socks lebih lambat daripada HTTP CONNECT biasa
        connect = 8.0 if proxy.startswith("socks") else 5.0
        return (connect, self.validate_timeout)

    def _refill(self) -> None:
        """Ambil + validasi sampai pool berisi `want` proxy (atau menyerah)."""
        with self.lock:
            if time.monotonic() - self.last_warm < self.warm_interval and self.pool:
                return
            self.last_warm = time.monotonic()

        for rnd in range(1, self.refill_rounds + 1):
            with self.lock:
                have = len(self.pool)
            need = self.want - have
            if need <= 0:
                return

            raw = scrape_proxies(self.sources, cache=self.cache, logger=self.log)
            if not raw:
                self.log(f"  refill round {rnd}: no candidates fetched")
            else:
                with self.lock:
                    known = {p for p, _ in self.pool}
                # acak, jangan ambil dari kepala daftar (selalu paling basi)
                cands = [p for p in raw
                         if p not in known and not self.cache.is_banned(p)]
                random.shuffle(cands)
                cands = cands[:self.validate_batch]
                self.log(f"  refill round {rnd}: validating {len(cands)} candidates "
                         f"(have {have}/{self.want})")

                found = self._validate_batch(cands, need)
                with self.lock:
                    for p, lat in found:
                        if p not in known:
                            self.pool.append((p, lat))
                            known.add(p)
                    self.pool.sort(key=lambda t: t[1])
                    have = len(self.pool)
                self.log(f"  refill round {rnd}: +{len(found)} -> pool {have}")

            if have >= self.want:
                return
            if rnd < self.refill_rounds:
                time.sleep(self.refill_backoff)

        with self.lock:
            have = len(self.pool)
        if have == 0:
            raise ProxyUnavailable(
                f"could not obtain any working proxy after {self.refill_rounds} refill rounds")
        self.log(f"  WARNING: pool only reached {have}/{self.want}")

    def _validate_batch(self, cands: list[str], want: int) -> list[tuple[str, float]]:
        """Validasi paralel, berhenti lebih awal begitu `want` proxy bagus didapat."""
        if not cands:
            return []
        good: list[tuple[str, float]] = []
        ex = ThreadPoolExecutor(max_workers=min(self.workers, len(cands)))
        try:
            futs = {ex.submit(check_proxy, p, self.target,
                              self._timeout_for(p), self.validator): p for p in cands}
            for fut in as_completed(futs):
                p = futs[fut]
                try:
                    ok, lat, reason = fut.result()
                except Exception as e:
                    ok, lat, reason = False, 0.0, classify_failure(e)
                if ok:
                    good.append((p, lat))
                    if len(good) >= want:
                        break
                else:
                    self.cache.ban(p, reason)
            # hentikan sisanya - ini yang membuat pengisian 60 detik jadi ~5 detik
            ex.shutdown(wait=False, cancel_futures=True)
        except Exception:
            ex.shutdown(wait=False, cancel_futures=True)
        return good

    # -- publik ------------------------------------------------------------
    def warm(self) -> None:
        """Isi pool sebelum dipakai. Melempar kalau tidak dapat proxy sama sekali."""
        if self.fixed:
            self.log(f"using fixed proxy: {self.fixed}")
            return
        self.log("warming proxy pool ...")
        self._refill()
        with self.lock:
            self.log(f"proxy pool ready: {len(self.pool)} live proxies")

    def take(self) -> str:
        """Ambil proxy valid, atau lempar ProxyUnavailable. Tidak pernah None."""
        if self.fixed:
            return self.fixed

        # isi ulang sebelum habis, bukan sesudahnya
        if len(self._snapshot()) < self.min_pool:
            self._refill()

        with self.lock:
            # utamakan kuartil tercepat, lewati yang sedang dipakai
            avail = [(p, l) for p, l in self.pool if p not in self.in_use]
            if not avail:
                avail = list(self.pool)
            if not avail:
                raise ProxyUnavailable("pool empty after refill")
            top = avail[:max(1, len(avail) // 4)]

            # hindari IP yang sama untuk pemakaian beruntun - terlalu cepat
            # mengulang satu IP itulah yang memicu rate limit per-IP
            fresh = [(p, l) for p, l in top if p not in self.recent]
            pick_from = fresh or top

            proxy, _ = random.choice(pick_from)
            self.in_use.add(proxy)
            self.recent.append(proxy)
            keep = max(1, min(len(self.pool) - 1, self.recent_avoid))
            while len(self.recent) > keep:
                self.recent.pop(0)
            return proxy

    def _snapshot(self) -> list[str]:
        with self.lock:
            return [p for p, _ in self.pool]

    def release(self, proxy: str | None) -> None:
        """Tandai proxy tidak terpakai lagi. Aman dipanggil dengan None."""
        if not proxy:
            return
        with self.lock:
            self.in_use.discard(proxy)

    def drop(self, proxy: str | None, reason: str = "failed_use") -> None:
        """Buang proxy dari pool dan ban sementara. Selalu dicatat."""
        if not proxy:
            return
        with self.lock:
            before = len(self.pool)
            self.pool = [(p, l) for p, l in self.pool if p != proxy]
            self.in_use.discard(proxy)
            after = len(self.pool)
        self.cache.ban(proxy, reason)
        if before != after or reason == "failed_use":
            self.log(f"dropped proxy {proxy} ({reason}) -> {after} left")

    def proxies_for(self, proxy: str) -> dict[str, str]:
        """Dict proxies untuk dipakai di requests."""
        return proxies_for(proxy)

    def stats(self) -> str:
        with self.lock:
            return f"{len(self.pool)} live / {len(self.in_use)} in use"


def attempt_with_rotation(pool: ProxyPool, work: Callable[[str], Any], *,
                          attempts: int = 5, retry_delay: float = 5.0,
                          logger: Callable[[str], None] = _default_log
                          ) -> tuple[Any, str]:
    """Jalankan `work(proxy)` dengan rotasi proxy saat gagal.

    `work` menerima string proxy dan mengembalikan hasil. Kontrak error:

      ProxyFailure  -> proxy-nya rusak: ban lalu ganti
      RateLimited   -> target yang membatasi, bukan salah proxy: proxy
                       dikembalikan ke pool, coba lagi dengan IP lain
      lainnya       -> error di kode sendiri. Tetap coba ulang dengan proxy baru
                       (bisa jadi datanya bergantung), tapi JANGAN salahkan proxy.

    Mengembalikan (hasil, proxy_yang_dipakai). Melempar ProxyUnavailable kalau habis.
    """
    last_exc: BaseException | None = None

    for attempt in range(1, attempts + 1):
        proxy = None
        try:
            proxy = pool.take()
            logger(f"using proxy: {proxy}  [{pool.stats()}]")
            result = work(proxy)
            pool.release(proxy)
            return result, proxy
        except ProxyFailure as e:
            logger(f"  ! proxy failed ({e.reason}): {str(e)[:120]}")
            pool.drop(proxy, e.reason)
            last_exc = e
        except RateLimited as e:
            logger(f"  ! rate limited: {str(e)[:120]}")
            pool.release(proxy)
            last_exc = e
        except ProxyUnavailable:
            raise
        except Exception as e:
            # Bug atau bentuk response yang tak terduga BUKAN salah proxy.
            # Membuang proxy di sini akan menghabiskan seluruh pool karena
            # satu error kode saja.
            logger(f"  ! error: {type(e).__name__}: {str(e)[:160]}")
            pool.release(proxy)
            last_exc = e
        finally:
            # jangan sampai in_use bocor, apa pun yang terjadi
            if proxy:
                pool.release(proxy)

        if attempt < attempts:
            time.sleep(retry_delay)

    raise ProxyUnavailable(f"gave up after {attempts} proxy attempts (last: {last_exc})")
