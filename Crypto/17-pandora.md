# Kaito CTF - Pandora

- Write-Up Author: reybong
- Category: Crypto
- Flag: `KAITO{pandora_holds_the_kuroba_legacy}`

## Challenge Description

> Toichi Kuroba spent his life searching for the Pandora gem. After his death, Kaito inherited more than a stage name — he inherited sealed research. A letter, a catalog entry, and an encrypted file are all that remain.

**Target File:** `research.enc`

## Analisis

File `research.enc` memiliki ukuran 66 byte. Berdasarkan analisis struktur binary, 66 byte tersebut terbagi menjadi:
- 12 byte: `nonce`
- 38 byte: `ciphertext`
- 16 byte: `authentication tag`

Struktur ini cocok dengan format **AES-256-GCM**.

Petunjuk dari korespondensi Toichi Kuroba mengekstrak 3 kata kunci:
- *who taught you magic* → `toichi`
- *what stone we chased* → `pandora`
- *what family you belong to* → `gem`

Passphrase yang dibentuk adalah `toichi:pandora:gem`. SHA-256 hash dari passphrase ini menghasilkan 32-byte (256-bit) AES key:
`1b2b11f457fd31034c1167d3e9b5856e73694841d00f12224a0daae4272d2684`

Ciphertext disajikan ke `AESGCM(key).decrypt(nonce, ciphertext + tag, None)` untuk memperoleh plaintext flag.

## Langkah Menemukan Flag

1. Susun key phrase `toichi:pandora:gem` dari hint surat Toichi Kuroba.
2. Derivasi 32-byte AES key menggunakan SHA-256 hash dari key phrase.
3. Parse `research.enc` menjadi 12-byte nonce, 38-byte ciphertext, dan 16-byte tag.
4. Dekripsi AES-256-GCM untuk mengekstrak plaintext flag.

Script otomatisasi eksploitasi (`solve.py`):

```python
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = Path("research.enc").read_bytes()

# Parse AES-GCM structure
nonce = data[:12]
ciphertext = data[12:-16]
tag = data[-16:]

# Recover key from clues
key_phrase = b"toichi:pandora:gem"
key = hashlib.sha256(key_phrase).digest()

# AES-256-GCM decrypt
aes = AESGCM(key)
encrypted = ciphertext + tag
plaintext = aes.decrypt(nonce, encrypted, None)

print("[+] Plaintext:", plaintext.decode())
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
```

**Flag:** `KAITO{pandora_holds_the_kuroba_legacy}`
