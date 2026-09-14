# Kaito CTF - Freewill

- Write-Up Author: reybong
- Category: Misc
- Flag: `KAITO{authorship_was_never_yours}`

## Challenge Description

> Diberikan berkas Python `freewill.py` serta tiga berkas terenkripsi (`ledger.enc`, `oracle.enc`, `vault.enc`). Selesaikan teka-teki logika array terselubung untuk membuka rahasia enkripsi.

**Target File:** `freewill.py`, `ledger.enc`

## Analisis

Di dalam file `freewill.py`, terdapat array terselubung `_ARCHIVE`:
```python
ARCHIVE = [193, 212, 217, 207, 233, 187, 238, 229, 243, 243, 251, 139, 212, 134, 153, 154, 157, 164]
```

Melalui fungsi `unseal(payload, seed=0xA7)` yang melakukan dekoding XOR `v ^ seed ^ ((i * 5 + 13) & 0xFF)`, dihasilkan string rahasia: `b"kaito:branch:omega"`.

String ini menjadi key material untuk derivasi kunci SHA-256:
`key = hashlib.sha256(b"kaito:branch:omega").digest()`

File `ledger.enc` berukuran 61 byte. Karena 61 bukan kelipatan 16, algoritma enkripsi yang digunakan adalah **AES-GCM** (12-byte nonce + ciphertext + 16-byte authentication tag).

Dekripsi AES-GCM dengan `nonce = encrypted[:12]` dan `ciphertext = encrypted[12:]` mengekstrak flag utama.

## Langkah Menemukan Flag

1. Ekstrak string terselubung `kaito:branch:omega` dari array `_ARCHIVE` via fungsi `unseal`.
2. Hitung SHA-256 hash dari string `kaito:branch:omega` untuk mendapatkan kunci AES 32-byte.
3. Pisahkan 12-byte nonce dan ciphertext+tag dari `ledger.enc`.
4. Dekripsi data menggunakan `AESGCM(key).decrypt(nonce, ciphertext, None)`.

Script otomatisasi eksploitasi (`solve.py`):

```python
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARCHIVE = [193, 212, 217, 207, 233, 187, 238, 229, 243, 243, 251, 139, 212, 134, 153, 154, 157, 164]

def unseal(payload, seed=0xA7):
    return bytes(v ^ seed ^ ((i * 5 + 13) & 0xFF) for i, v in enumerate(payload))

canon = unseal(ARCHIVE)
key = hashlib.sha256(canon).digest()

encrypted = Path("ledger.enc").read_bytes()
nonce = encrypted[:12]
ct = encrypted[12:]

plaintext = AESGCM(key).decrypt(nonce, ct, None)
print(plaintext.decode())
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
```

**Flag:** `KAITO{authorship_was_never_yours}`
