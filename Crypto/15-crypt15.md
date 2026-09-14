# Kaito CTF - WhatsApp crypt15 Backup

- Write-Up Author: reybong
- Category: Crypto
- Flag: `KAITO{signal_protocol_crypt15_backup_decrypted}`

## Challenge Description

> We are given a WhatsApp encrypted backup file (`msgstore.db.crypt15`) along with two clues: a local shard (`deadbeefcafebabe1337133713371337`) and an unlock hint (`0123456789abcdef0123456789abcdef`).

**Target File:** `msgstore.db.crypt15`

## Analisis

Ukuran file `msgstore.db.crypt15` adalah 983 byte. Bagian awal file diawali dengan struktur Protobuf (byte pertama `0x85` menentukan panjang header 133 byte). Dalam header ini tersimpan IV sepanjang 16 byte (`ad9b9e830520128a8414df7a0335c1c9`).

Penggabungan dua clue 16-byte hex shard (`deadbeefcafebabe1337133713371337`) dan 16-byte hex hint (`0123456789abcdef0123456789abcdef`) menghasilkan 32-byte (256-bit) root key:
`deadbeefcafebabe13371337133713370123456789abcdef0123456789abcdef`

Untuk mendapatkan kunci dekripsi AES-256-GCM, dilakukan derivasi kunci (KDF) standar WhatsApp crypt15 menggunakan HMAC-SHA256:
1. `k1 = HMAC-SHA256(key=0x00*32, data=root_key)`
2. `aes_key = HMAC-SHA256(key=k1, data=b"backup encryption\x01")`

Hal penting yang perlu diperhatikan pada struktur footer crypt15 adalah pembacaan GCM authentication tag. 32 byte terakhir pada file terbagi menjadi GCM tag pada `data[-32:-16]` dan footer pada `data[-16:]`. Setelah dekripsi AES-256-GCM berhasil, hasil dekripsi didekompresi menggunakan `zlib` hingga menghasilkan SQLite database `msgstore.db` (16.384 byte). Di dalam tabel `message`, ditemukan flag yang dicari.

## Langkah Menemukan Flag

1. Gabungkan kedua clue 16-byte menjadi 32-byte root key.
2. Derivasi kunci AES menggunakan KDF HMAC-SHA256 WhatsApp.
3. Ekstrak IV (`data[8:24]`), ciphertext (`data[135:-32]`), dan GCM tag (`data[-32:-16]`).
4. Dekripsi ciphertext dengan `AES-256-GCM` dan dekompresi data dengan `zlib.decompress()`.
5. Buka `msgstore.db` dengan SQLite dan jalankan `SELECT text_data FROM message;`.

Script otomatisasi eksploitasi (`solve.py`):

```python
from pathlib import Path
import hashlib
import hmac
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = Path("msgstore.db.crypt15").read_bytes()

# Two challenge clues
root_key = bytes.fromhex(
    "deadbeefcafebabe1337133713371337"
    "0123456789abcdef0123456789abcdef"
)

# WhatsApp crypt15 KDF
k1 = hmac.new(
    b"\x00" * 32,
    root_key,
    hashlib.sha256
).digest()

aes_key = hmac.new(
    k1,
    b"backup encryption\x01",
    hashlib.sha256
).digest()

# crypt15 header & IV
iv = data[8:24]

# Footer layout used by this backup
ciphertext = data[135:-32]
tag = data[-32:-16]

# AES-256-GCM
plaintext = AESGCM(aes_key).decrypt(
    iv,
    ciphertext + tag,
    None
)

# zlib -> SQLite
db = zlib.decompress(plaintext)

Path("msgstore.db").write_bytes(db)
print("[+] Decrypted successfully: msgstore.db")
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
sqlite3 msgstore.db "SELECT text_data FROM message;"
```

**Flag:** `KAITO{signal_protocol_crypt15_backup_decrypted}`
