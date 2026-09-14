# Kaito CTF - Neko Haven (VIP Lounge Access)

- Write-Up Author: reybong
- Category: Beginner
- Flag: `Kaito{n3k0_c4fe_sip_purr_fl4g_991}`

## Challenge Description

> Neko Haven menyimulasikan halaman akses VIP Lounge untuk bertemu Sir Meowsalot. Pengunjung diminta memasukkan passcode rahasia untuk mendapatkan token/flag VIP.

**Target URL:** `http://31.97.37.38:1341/`

## Analisis

Aplikasi web Neko Haven menyajikan antarmuka VIP Lounge tempat pengguna diminta memasukkan passcode rahasia untuk menemui *Sir Meowsalot*.

Dari hasil analisis file `index.html` dan `Dockerfile`, ditemukan bahwa aplikasi disajikan secara statis via Nginx tanpa adanya server backend pemroses otentikasi.

Ditemukan celah **Client-Side Authentication Bypass & Hardcoded Sensitive Data Exposure**:
- Logika otentikasi berada sepenuhnya di sisi klien (`enterLounge()` pada file JavaScript `index.html`).
- Rahasia passcode dan flag disimpan langsung dalam kode JavaScript dengan enkoding Base64 sederhana:
  - Passcode: `atob("bWVvd19wdXJyXzIwMjY=")` $\rightarrow$ `meow_purr_2026`
  - Flag: `atob("S2FpdG97bjNrMF9jNGZlX3NpcF9wdXJyX2ZsNGdfOTkxfQ==")` $\rightarrow$ `Kaito{n3k0_c4fe_sip_purr_fl4g_991}`
- Pengguna dapat mengekstrak rahasia dan flag langsung dari inspect element / source code tanpa memerlukan validasi dari server.

<!-- SCREENSHOT: tampilan web Neko Haven -->
![Tampilan web Neko Haven](../assets/neko-haven-web.png)

## Langkah Menemukan Flag

1. Buka kode sumber `index.html` menggunakan fitur *View Source* atau *Developer Tools* pada browser.
2. Temukan fungsi JavaScript `enterLounge()` yang melakukan dekode string Base64.
3. Lakukan dekode string `bWVvd19wdXJyXzIwMjY=` untuk mendapatkan passcode `meow_purr_2026`, atau langsung dekode string flag `S2FpdG97bjNrMF9jNGZlX3NpcF9wdXJyX2ZsNGdfOTkxfQ==`.
4. Masukkan passcode `meow_purr_2026` pada form VIP Lounge untuk menampilkan flag secara langsung.

Script otomatisasi eksploitasi (`solve.py`):

```python
import base64, re, sys, requests

url = sys.argv[1] if len(sys.argv) > 1 else "http://31.97.37.38:1341/"

# 1. Ambil source HTML dari server
if url.startswith("http://") or url.startswith("https://"):
    html_content = requests.get(url).text
else:
    with open(url, "r", encoding="utf-8") as f:
        html_content = f.read()

# 2. Ekstrak string flag Base64 menggunakan regex
match = re.search(r'atob\s*\(\s*["\'](S2Fp[A-Za-z0-9+/=]+)["\']\s*\)', html_content)
if match:
    flag = base64.b64decode(match.group(1)).decode("utf-8")
    print(f"[+] FLAG: {flag}")
else:
    print("[-] Flag pattern not found")
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py http://31.97.37.38:1341/
```

**Flag:** `Kaito{n3k0_c4fe_sip_purr_fl4g_991}`
