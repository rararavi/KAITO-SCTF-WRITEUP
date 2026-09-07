# Kaito CTF - Freewill

- Write-Up Author: Ravi
- Category: Misc
- Flag: `KAITO{you_chose_nothing_i_chose_everything}`

## Challenge Description

> Kaito Kuroba built a story about choice — the same way a magician builds an illusion of free will in the audience.
> You will stand at crossroads. Each decision will feel like yours.
> But the phantom thief wrote the ending before you arrived.

## Analisis

Diberikan tiga file: `freewill.py`, `.atlas`, dan `ledger.enc`.

Petunjuknya ada di kalimat berikut:

```
"You will stand at crossroads. Each decision will feel like yours."
"But the phantom thief wrote the ending before you arrived."
```

Kalimat ini mengindikasikan bahwa pilihan yang tampak bebas sebenarnya sudah ditentukan sebelumnya — dan flag-nya sudah "ditulis" lebih dulu di dalam data terenkripsi.

## Langkah Menemukan Flag

Setelah menganalisis `freewill.py`, `.atlas`, dan `ledger.enc`, alur untuk mendapatkan flag adalah sebagai berikut.

1. **Recover `fate_key` dari `_ARCHIVE`** menggunakan fungsi `_unseal()`:

   ```python
   ARCHIVE = [
       193, 212, 217, 207, 233, 187, 238, 229,
       243, 243, 251, 139, 212, 134, 153, 154,
       157, 164
   ]

   def unseal(payload, seed=0xA7):
       return bytes(
           v ^ seed ^ ((i * 5 + 13) & 0xff)
           for i, v in enumerate(payload)
       )

   fate_key = unseal(ARCHIVE)

   print("[+] Fate key:", fate_key.decode())
   ```

   Output:

   ```
   [+] Fate key: kaito:branch:omega
   ```

2. **Verifikasi dengan `.atlas`** — nilai `kaito:branch:omega` juga tersimpan di `.atlas` sebagai `fate_key`, sehingga dipastikan sebagai key yang benar.

3. **Turunkan key XOR** dari `fate_key` menggunakan SHA-256 (32 byte), lalu gunakan untuk repeating-key XOR terhadap `ledger.enc`.

   Full script otomatis:

   ```python
   import base64
   import hashlib
   import json
   from pathlib import Path

   # 1. Recover archive key
   ARCHIVE = [
       193, 212, 217, 207, 233, 187, 238, 229,
       243, 243, 251, 139, 212, 134, 153, 154,
       157, 164
   ]

   def unseal(payload, seed=0xA7):
       return bytes(
           v ^ seed ^ ((i * 5 + 13) & 0xff)
           for i, v in enumerate(payload)
       )

   fate_key = unseal(ARCHIVE)
   print("[+] Fate key:", fate_key.decode())

   # 2. Decode .atlas
   atlas = Path(".atlas").read_bytes()
   atlas = base64.b64decode(atlas)
   data = json.loads(atlas)
   print("[+] Atlas fate_key:", data["fate_key"])

   # 3. Read encrypted ledger
   ciphertext = Path("ledger.enc").read_bytes()
   print("[+] Ciphertext length:", len(ciphertext))

   # 4. Derive XOR key
   key = hashlib.sha256(fate_key).digest()
   print("[+] SHA256 key:", key.hex())

   # 5. Repeating-key XOR
   plaintext = bytes(
       c ^ key[i % len(key)]
       for i, c in enumerate(ciphertext)
   )

   print("[+] Plaintext:", plaintext.decode())
   ```

4. Output script:

   ```
   [+] Fate key: kaito:branch:omega
   [+] Atlas fate_key: kaito:branch:omega
   [+] Ciphertext length: 43
   [+] SHA256 key: 56aa3ebff7e0628f75657dcc4acb779d468d973b5d4a2382aa438a58d4d9bf39
   [+] Plaintext: KAITO{you_chose_nothing_i_chose_everything}
   ```

## Kesimpulan

`fate_key` yang tersembunyi di `_ARCHIVE` dan `.atlas` di-hash dengan SHA-256 untuk membentuk key, lalu digunakan untuk repeating-key XOR terhadap `ledger.enc`. Nama challenge "Freewill" menyiratkan bahwa "pilihan" yang tampak bebas sebenarnya sudah ditentukan sejak awal.

**Flag:** `KAITO{you_chose_nothing_i_chose_everything}`
