# Kaito CTF - Mamma Mia! Disastro nel forno! (Pizza Syndicate)

- Write-Up Author: reybong
- Category: Forensic / Reverse / Crypto
- Flag: `Kaito{n4p0l1_s4uc3_m4f14_m3m0ry_c4rv1ng_p1zz4_1924}`

## Challenge Description

> At 03:42 AM, the smart wood-fired oven at Restorante Don Peperoni spiked to 500°C, destroying a 48-hour batch of sacred sourdough crust. Before shutting the oven down, Luigi captured two important artifacts: `kitchen_tap.pcap` and `oven_core_ram.raw`.

**Target File:** `kitchen_tap.pcap`, `oven_core_ram.raw`

## Analisis

Eksploitasi dilakukan dengan menggabungkan analisis jaringan dan memori:

1. **Analisis PCAP (`kitchen_tap.pcap`)**:
   - `HWID`: `NP-9000-8F3A-44C1-229E`
   - `Vault Name`: `peperoni_heritage_1924`
   - `Cipher`: `AES-256-CBC`
   - `Cartel String`: `Vendetta1924`

2. **Analisis Memori (`oven_core_ram.raw`) & Reverse Engineering**:
   - Ekstrak file ELF implant pada offset `0x520000`.
   - String terdeobfuscate (XOR `0x5c`) memberikan string cartel `::CrustCartelVendetta1924::` dan header `PIZZA_SAUCE_V2`.
   - Lokasi encrypted vault berada pada offset `0x880000` di RAM.
   - IV sepanjang 16 byte berada di `414fc9d80ebdc97108b11dddd898075b` dan ciphertext berukuran 688 byte.

3. **Derivasi Kunci AES-256**:
   - Input key material: `HWID + cartel + vault` = `NP-9000-8F3A-44C1-229E::CrustCartelVendetta1924::peperoni_heritage_1924`
   - SHA-256 hash dari string tersebut menghasilkan kunci 32-byte (256-bit) AES.
   - Dekripsi AES-256-CBC terhadap ciphertext menghasilkan resep rahasia dan flag.

## Langkah Menemukan Flag

1. Cari parameter dekripsi dari pcap log (`HWID` dan `vault_id`).
2. Ekstrak implant ELF dan ciphertext vault `PIZZA_SAUCE_V2` dari RAM dump `oven_core_ram.raw`.
3. Hitung SHA-256 hash dari kombinasi string `HWID + cartel + vault`.
4. Dekripsi ciphertext menggunakan AES-256-CBC dan IV yang diekstrak dari header vault.

Script otomatisasi eksploitasi (`solve.py`):

```python
from pathlib import Path
import hashlib
from Crypto.Cipher import AES

RAM_FILE = "oven_core_ram.raw"
VAULT_OFFSET = 0x880000
HEADER = b"PIZZA_SAUCE_V2"

data = Path(RAM_FILE).read_bytes()

hwid = "NP-9000-8F3A-44C1-229E"
vault = "peperoni_heritage_1924"
cartel = "::CrustCartelVendetta1924::"

key_material = hwid + cartel + vault
key = hashlib.sha256(key_material.encode()).digest()

length_offset = VAULT_OFFSET + len(HEADER)
cipher_length = int.from_bytes(data[length_offset:length_offset + 4], "little")
body_offset = length_offset + 4

iv = data[body_offset:body_offset + 16]
ciphertext = data[body_offset + 16:body_offset + 16 + cipher_length]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

padding = plaintext[-1]
if 1 <= padding <= AES.block_size:
    plaintext = plaintext[:-padding]

print(plaintext.decode(errors="replace"))
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
```

**Flag:** `Kaito{n4p0l1_s4uc3_m4f14_m3m0ry_c4rv1ng_p1zz4_1924}`
