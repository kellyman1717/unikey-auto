# unikey-auto

Bot registrasi otomatis untuk getunikey.ai. Membuat akun, mengambil API key,
dan memantau kredit — semuanya lewat HTTP tanpa browser.

Setiap akun dibuat dengan wallet baru yang di-generate otomatis, lalu dipakai
untuk sign-up lewat endpoint Web3. Cloudflare Turnstile dilewati memakai
solver terpisah.

## Alur

1. Ambil daftar proxy dari beberapa sumber publik, validasi, simpan yang hidup
2. Generate wallet EVM baru
3. Selesaikan Cloudflare Turnstile lewat Boterdrop Solver
4. Minta challenge ke `/api/oauth/web3/challenge`
5. Tanda tangani pesan (EIP-191) dengan private key wallet
6. Kirim ke `/api/oauth/web3/verify` — akun otomatis dibuat
7. Buat API key dan tampilkan nilainya
8. Baca kredit, tulis ke `accounts.json` dan `hasil.txt`

## Kebutuhan

- Python 3.10+
- Boterdrop Solver harus jalan di `http://127.0.0.1:8000`

```
pip install requests eth-account "requests[socks]"
```

## Cara pakai

Jalankan solver dulu di terminal terpisah:

```
cd Boterdrop-Solver
python api_server.py
```

Lalu jalankan botnya:

```
python unikey_bot.py create 1     # buat 1 akun
python unikey_bot.py create 5     # buat 5 akun
python unikey_bot.py refresh      # perbarui kredit semua akun
python unikey_bot.py list         # tampilkan akun
python unikey_bot.py export       # tulis ulang hasil.txt
python unikey_bot.py proxy        # tes pool proxy saja
```

Satu akun biasanya selesai dalam 30-60 detik. Kalau muncul pesan rate limit,
bot otomatis berganti proxy dan mencoba lagi.

## Output

- `accounts.json` — data lengkap: wallet, private key, API key, kredit, proxy
- `hasil.txt` — ringkasan: akun dan API key saja

Private key disimpan apa adanya di `accounts.json` karena dipakai untuk login
ulang saat `refresh`. Jangan sebarkan file itu.

## Pakai API key-nya

Endpoint kompatibel OpenAI:

```
curl https://www.getunikey.ai/v1/models \
  -H "Authorization: Bearer <api_key>"
```

## Konfigurasi

Semua pengaturan ada di `config.json`.

| Key | Arti |
| --- | --- |
| `solver_url` | Alamat Boterdrop Solver |
| `proxy` | Isi kalau mau pakai proxy sendiri, biarkan `null` untuk pakai sumber publik |
| `min_pool` | Jumlah proxy hidup yang dijaga |
| `proxy_attempts` | Berapa kali ganti proxy sebelum menyerah |
| `token_name` | Nama API key yang dibuat |
| `unlimited_quota` | API key tanpa batas kuota |
| `delay_between_accounts` | Jeda antar akun (detik) |

## Sumber proxy

Daftar sumber dan hasil ukurnya ada di `PROXY_SOURCES` dalam `proxypool.py`.
Yang paling produktif: monosans, roosterkid (SOCKS), dan proxifly. Sumber yang
sudah mati tidak dipakai.

Proxy gratis punya tingkat keberhasilan sekitar 10% dan cepat mati, jadi bot
selalu memvalidasi sebelum memakai dan otomatis membuang yang gagal. Untuk
pemakaian dalam jumlah besar, proxy berbayar jauh lebih stabil.

## proxypool.py

Logika proxy dipisah ke `proxypool.py` supaya bisa dipakai skrip lain, bukan
cuma bot ini. Modulnya berdiri sendiri: tidak mengimpor apa pun dari
`unikey_bot.py`, dan target validasinya bisa diarahkan ke situs mana saja.

Isi modulnya:

| Bagian | Kegunaan |
| --- | --- |
| `ProxyPool` | Pool proxy yang selalu terisi. `take()` selalu memberi proxy valid, atau melempar `ProxyUnavailable` |
| `attempt_with_rotation` | Jalankan tugas dengan rotasi proxy otomatis saat gagal |
| `proxies_for` | Dict proxies untuk `requests` (dua key sekaligus) |
| `proxied_session` | Session `requests` yang tidak bisa dibelokkan proxy dari luar |
| `ProxyFailure` / `RateLimited` | Pembeda error: salah proxy, atau target yang membatasi |
| `PROXY_SOURCES` | Daftar sumber proxy gratis |
| `normalize_proxy` | Ubah baris sumber jadi `scheme://ip:port` |

Contoh pakai di skrip lain:

```python
import requests
from proxypool import ProxyPool, attempt_with_rotation

pool = ProxyPool(target="https://situsku.com/api/ping")
pool.warm()

def kerja(proxy):
    return requests.get("https://situsku.com/data",
                        proxies=pool.proxies_for(proxy), timeout=20).json()

data, proxy_dipakai = attempt_with_rotation(pool, kerja)
```

Kalau target butuh pengecekan isi response, beri `validator`:

```python
def cek(resp):
    return resp.status_code == 200 and resp.json().get("ok") is True

pool = ProxyPool(target="https://situsku.com/api/status", validator=cek)
```

Tingkat keberhasilan proxy gratis berbeda-beda per situs, jadi `target` sebaiknya
diarahkan ke endpoint ringan milik situs tujuan sendiri. Proxy yang lolos
validasi di satu situs belum tentu bisa dipakai di situs lain.

## Catatan soal kredit

Registrasi memberi bonus pendaftaran sebesar 250.000 unit internal. Yang
ditampilkan di halaman web adalah nilai itu dibagi
`custom_currency_exchange_rate` (10000), jadi terlihat sebagai 25 Credits —
bukan 25.000. Nilai internal dan nilai tampilan adalah hal yang sama, hanya
berbeda skala penyajian.

## Struktur

```
unikey_bot.py    skrip utama
proxypool.py     modul pool proxy, bisa dipakai skrip lain
config.json      pengaturan
accounts.json    hasil lengkap (berisi private key, tidak di-push)
hasil.txt        ringkasan hasil
apikey.txt       daftar API key saja
```
