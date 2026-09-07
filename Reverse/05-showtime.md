# Kaito CTF - Showtime

- Write-Up Author: Ravi
- Category: Reverse
- Flag: `KAITO{its_showtime_ladies_and_gentlemen}`

## Challenge Description

Diberikan sebuah file Python (encoder) beserta file terenkripsi `.enc`. Tujuan kita adalah melakukan reverse engineering terhadap logika encoding untuk memulihkan plaintext.

## Analisis

File challenge terdiri dari file Python dan file `.enc`.

<!-- SCREENSHOT: file yang diberikan -->
![File challenge Showtime](../assets/05-showtime-files.png)

Di dalam file Python terdapat konstanta yang bukan sekadar kumpulan integer biasa:

```python
_ARCHIVE = [54, 37, 37, 37, 43, 45, 121, 43, 36, 31, 22, 17, 75, 7, 3, 1, 26, 20, 14, 119, 124]
```

Nilai `_ARCHIVE` ini adalah payload yang di-unseal untuk mendapatkan credential tersembunyi.

## Langkah Menemukan Flag

1. **Recover hidden value dari `_ARCHIVE`** dengan fungsi `unseal`:

   ```python
   ARCHIVE = [
       54, 37, 37, 37, 43, 45, 121, 43, 36, 31,
       22, 17, 75, 7, 3, 1, 26, 20, 14, 119, 124
   ]

   def unseal(payload, seed=0x5A):
       return bytes(
           v ^ seed ^ ((i * 3 + 7) & 0xFF)
           for i, v in enumerate(payload)
       )

   result = unseal(ARCHIVE)

   print(result)
   ```

   Output:

   ```
   b'kuroba:magic:showtime'
   ```

2. **Turunkan key** dari nilai tersebut dengan SHA-256:

   ```python
   import hashlib

   canon = b"kuroba:magic:showtime"

   key = hashlib.sha256(canon).digest()

   print(key.hex())
   ```

   Hasil key:

   ```
   5480cd3242b09541cba7547a1eb35618f3086f9c6d5f4d1888e678b7756d0d7e
   ```

3. **Buka file `.enc`** dan amati hexadecimal-nya untuk memastikan bentuk ciphertext.

   <!-- SCREENSHOT: hexdump program.enc -->
   ![Hexdump program.enc](../assets/05-showtime-hexdump.png)

4. **Dekripsi** file `.enc` dengan repeating-key XOR memakai key hasil SHA-256:

   ```python
   from pathlib import Path
   import hashlib

   # Hidden value recovered from _ARCHIVE
   canon = b"kuroba:magic:showtime"

   # Generate key
   key = hashlib.sha256(canon).digest()

   # Read encrypted file
   encrypted = Path("program.enc").read_bytes()

   # XOR decrypt
   plaintext = bytes(
       c ^ key[i % len(key)]
       for i, c in enumerate(encrypted)
   )

   print(plaintext.decode())
   ```

5. Output script menampilkan flag.

## Kesimpulan

Program menyembunyikan sebuah nilai di dalam `_ARCHIVE` menggunakan operasi XOR. Nilai tersebut di-hash dengan SHA-256 untuk membentuk key, lalu key tersebut dipakai sebagai repeating-key XOR untuk mendekripsi file `.enc`.

**Flag:** `KAITO{its_showtime_ladies_and_gentlemen}`
