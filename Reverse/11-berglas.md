# Kaito CTF - The Berglas Effect

- Write-Up Author: Ravi
- Category: Reverse
- Flag: `KAITO{any_card_any_number_no_method_known}`

## Challenge Description

> THE BERGLAS EFFECT  
> Any card. Any number.
>
> No forces. No touches. No explanation.
>
> Kaito is not supposed to know your choices.

Challenge diberikan dalam bentuk ZIP yang berisi:

```text
berglas.py
deck.enc
witness/
├── elysium.log
├── glasshouse.log
├── midnight.log
├── mirage.log
└── parlor.log
```

Tujuan challenge adalah membongkar `deck.enc` dan mendapatkan flag.

---

## Write up

### Analisis Source Code

Pertama, buka `berglas.py`.

Di dalam source terdapat dua nilai penting:

```python
_STACK_FP = "8eade2b59b78b709"

_MASKED = [
    215, 201, 213, 249, 245, 241, 248, 184,
    156, 151, 142, 135, 143, 226, 182, 172,
    163, 89, 84, 90
]
```

Fungsi `_load_stack()` terlihat seperti membaca `deck.enc`, tetapi sebenarnya hanya mengembalikan deck palsu:

```python
def _load_stack() -> list[str]:
    payload = Path("deck.enc")
    if payload.exists():
        return ["??"] * 52
    return ["??"] * 52
```

Kemudian `_resolve()` juga tidak benar-benar mengambil kartu dari deck:

```python
def _resolve(card: str, position: int) -> str:
    stack = _load_stack()
    idx = position - 1
    if idx < 0 or idx >= len(stack):
        raise ValueError("position out of range")
    _ = stack[idx]
    return card
```

Artinya, bagian ini adalah **decoy**. File `deck.enc` tidak didekripsi oleh program utama.

---

## Analisis Witness

Lima file pada folder `witness/` memberikan pasangan kartu dan posisi:

```text
7H @ 39
2C @ 23
AS @ 17
KD @ 4
TC @ 52
```

Masing-masing memiliki `witness_seal`, misalnya:

```text
card=AS
position=17
witness_seal=9c155011778567601fec
stack_mark=8eade2b59b78b709
```

Source code menunjukkan bagaimana seal dibuat:

```python
def _spectator_seal(card: str, position: int) -> str:
    material = f"{card}@{position}:{_STACK_FP}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]
```

Jadi witness hanya berfungsi sebagai **verifikasi bahwa pasangan card/position memang bagian dari challenge**. `_STACK_FP` bukan key AES secara langsung.

Tema challenge juga mengarah ke Berglas/ACAAN (*Any Card At Any Number*).

---

# Recover Hidden Canon

Bagian paling menarik adalah `_MASKED`.

Nilainya merupakan 20 byte:

```python
_MASKED = [
    215, 201, 213, 249, 245, 241, 248, 184,
    156, 151, 142, 135, 143, 226, 182, 172,
    163, 89, 84, 90
]
```

Tidak ada fungsi `unseal()` yang langsung diberikan seperti pada challenge sebelumnya. Jadi kita perlu melakukan reverse engineering terhadap masking tersebut.

Dari pola byte dan konteks challenge, `_MASKED` dapat dibalik menggunakan XOR dengan seed dan mask yang bergantung pada index:

```python
MASKED = [
    215, 201, 213, 249, 245, 241, 248, 184,
    156, 151, 142, 135, 143, 226, 182, 172,
    163, 89, 84, 90
]

def unmask(payload, seed=0x3E):
    return bytes(
        v ^ seed ^ ((i * 7 + 0x8B) & 0xff)
        for i, v in enumerate(payload)
    )

canon = unmask(MASKED)

print(canon)
```

Output:

```text
b'berglas:acaan:effect'
```

Jadi nilai canon yang digunakan untuk proses berikutnya adalah:

```text
berglas:acaan:effect
```

---

# Derive AES Key

Setelah mendapatkan canon, lakukan SHA-256 seperti pola crypto challenge sebelumnya:

```python
import hashlib

canon = b"berglas:acaan:effect"

key = hashlib.sha256(canon).digest()

print(key.hex())
```

Hasil:

```text
b817d430a043d4c96a368039409b6c6004919b07321e5ededbd5ae067608914e
```

Key ini memiliki panjang 32 byte sehingga cocok untuk AES-256.

---

# Analisis `deck.enc`

Sekarang cek ukuran dan struktur file:

```python
from pathlib import Path

encrypted = Path("deck.enc").read_bytes()

print(len(encrypted))
print(encrypted[:12].hex())
print(encrypted[-16:].hex())
```

Output:

```text
798
f4e5e4b8d96d0d6bfc184e10
3b68ba79956a9cfe2e5592ef56b332ba
```

Ukuran dan struktur tersebut cocok dengan format AES-GCM:

```text
12 bytes  -> nonce
N bytes   -> ciphertext
16 bytes  -> authentication tag
```

Jadi:

```python
nonce = encrypted[:12]
ciphertext_and_tag = encrypted[12:]
```

---

# AES-GCM Decryption

Gunakan `cryptography`:

```python
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

# Recover canon
canon = b"berglas:acaan:effect"

# Derive AES-256 key
key = hashlib.sha256(canon).digest()

# Read encrypted file
encrypted = Path("deck.enc").read_bytes()

# AES-GCM layout
nonce = encrypted[:12]
ciphertext_and_tag = encrypted[12:]

# Decrypt
plaintext = AESGCM(key).decrypt(
    nonce,
    ciphertext_and_tag,
    None
)

print(plaintext.decode())
```

Output:

```json
{
  "performer": "Kaito",
  "effect": "Berglas / ACAAN",
  "method_published": false,
  "stack": [
    "TC",
    "9S",
    "5H",
    "JH",
    "JS",
    "5D",
    "QH",
    "9C",
    "TD",
    "7D",
    "2D",
    "6C",
    "8C",
    "AH",
    "KS",
    "3H",
    "QS",
    "AC",
    "JC",
    "6H",
    "KC",
    "8S",
    "KD",
    "4H",
    "7H",
    "7S",
    "JD",
    "8D",
    "AD",
    "8H",
    "2C",
    "4C",
    "4S",
    "TS",
    "3S",
    "QC",
    "6S",
    "KH",
    "5C",
    "2S",
    "9D",
    "9H",
    "7C",
    "TH",
    "QD",
    "4D",
    "3C",
    "AS",
    "2H",
    "5S",
    "3D",
    "6D"
  ],
  "flag": "KAITO{any_card_any_number_no_method_known}",
  "note": "The audience names the card and the number. The outcome was arranged earlier."
}
```

---

# Flag

Flag ditemukan langsung di plaintext hasil dekripsi:

```text
KAITO{any_card_any_number_no_method_known}
```

---

# Full Solver Script

Script lengkap untuk mendapatkan flag:

```python
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

# =========================
# 1. Recover hidden canon
# =========================

MASKED = [
    215, 201, 213, 249, 245, 241, 248, 184,
    156, 151, 142, 135, 143, 226, 182, 172,
    163, 89, 84, 90
]

def unmask(payload, seed=0x3E):
    return bytes(
        v ^ seed ^ ((i * 7 + 0x8B) & 0xff)
        for i, v in enumerate(payload)
    )

canon = unmask(MASKED)

print("[+] Canon:", canon.decode())


# =========================
# 2. Derive AES-256 key
# =========================

key = hashlib.sha256(canon).digest()

print("[+] AES key:", key.hex())


# =========================
# 3. Read encrypted deck
# =========================

encrypted = Path("deck.enc").read_bytes()

print("[+] Ciphertext length:", len(encrypted))


# =========================
# 4. Extract nonce
# =========================

nonce = encrypted[:12]
ciphertext_and_tag = encrypted[12:]

print("[+] Nonce:", nonce.hex())
print("[+] Tag:", encrypted[-16:].hex())


# =========================
# 5. AES-GCM decrypt
# =========================

plaintext = AESGCM(key).decrypt(
    nonce,
    ciphertext_and_tag,
    None
)

print("[+] Plaintext:")
print(plaintext.decode())
```

Running the script produces:

```text
[+] Canon: berglas:acaan:effect
[+] AES key: b817d430a043d4c96a368039409b6c6004919b07321e5ededbd5ae067608914e
[+] Ciphertext length: 798
[+] Nonce: f4e5e4b8d96d0d6bfc184e10
[+] Tag: 3b68ba79956a9cfe2e5592ef56b332ba
```

And the decrypted JSON contains:

```text
KAITO{any_card_any_number_no_method_known}
```

---

# Kesimpulan

Challenge ini menggunakan beberapa layer yang sengaja dibuat sebagai decoy:

```text
_MASKED
   │
   │ reverse masking
   ▼
berglas:acaan:effect
   │
   │ SHA-256
   ▼
AES-256 key
   │
   │ AES-GCM
   ▼
deck.enc
   │
   ▼
JSON
   │
   └── flag
```

`berglas.py` sendiri tidak melakukan dekripsi `deck.enc`; `_load_stack()` dan `_resolve()` hanya digunakan untuk membuat seolah-olah program dapat melakukan efek ACAAN.

Lima `witness/*.log` juga bukan key. File tersebut digunakan untuk memberikan bukti/jejak card-position dan memvalidasi `_STACK_FP`.

Kunci sebenarnya diperoleh dari `_MASKED`, kemudian di-hash dengan SHA-256. Hasil hash digunakan sebagai key AES-256-GCM untuk membuka `deck.enc`.

## Final Flag

```text
KAITO{any_card_any_number_no_method_known}
```
