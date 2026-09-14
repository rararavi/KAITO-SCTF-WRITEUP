# Kaito CTF - Disguises

- Write-Up Author: reybong
- Category: Beginner
- Flag: `KAITO{the_disguise_fools_eyes_not_the_timeline}`

## Challenge Description

> After Kaito Kid vanishes from the Beika Art Museum, four witnesses swear they saw him. Three are describing disguises planted to scatter the police. One statement matches the real escape. Find the truth. Open what Kid left behind.

**Target File:** `locker.enc`, `case_summary.txt`

## Analisis

Diberikan file `locker.enc` (47 byte) dan `case_summary.txt`. Dari 4 saksi yang ada, dilakukan evaluasi logika narasi:
1. **Officer Takagi (21:03 - North tower roof access)**: Logis, konsisten dengan rute pelarian glider Kid tepat setelah resital (21:00).
2. **Inspector Megure (21:05 - South gate)**: Decoy (pria bertopi Kid dengan postur tubuh terlalu berat).
3. **Museum Curator (21:12 - Main hall)**: Detail kostum salah (posisi monokel di mata kiri, seharusnya kanan).
4. **Stagehand (21:18 - Backstage)**: Timeline tidak masuk akal (area seharusnya sudah steril 18 menit setelah resital).

Kunci enkripsi diturunkan dari informasi saksi valid (Takagi): lokasi `north_tower` dan waktu `2103`, yang membentuk passphrase `north_tower:2103`. Kunci SHA-256 dari passphrase ini kemudian digunakan untuk dekripsi repeating-key XOR terhadap ciphertext `locker.enc`.

## Langkah Menemukan Flag

1. Identifikasi saksi valid (Officer Takagi) untuk mendapatkan komponen passphrase `north_tower:2103`.
2. Hitung SHA-256 hash dari passphrase `north_tower:2103` untuk menghasilkan 32-byte XOR key.
3. Dekripsi `locker.enc` menggunakan XOR terhadap SHA-256 key tersebut.

Script otomatisasi eksploitasi (`solve.py`):

```python
import hashlib

data = open("locker.enc", "rb").read()

# Passphrase diturunkan dari statement Officer Takagi:
# lokasi = "North tower roof access" -> north_tower
# waktu  = "21:03"                   -> 2103
passphrase = "north_tower:2103"

key = hashlib.sha256(passphrase.encode()).digest()
plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

print(f"[+] Plaintext: {plaintext.decode()}")
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
```

**Flag:** `KAITO{the_disguise_fools_eyes_not_the_timeline}`
