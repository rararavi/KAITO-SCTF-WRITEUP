# Kaito CTF - Showtime

- **Write-Up Author:** Ravi
- **Category:** Reverse
- **Flag:** `KAITO{its_showtime_ladies_and_gentlemen}`

## Challenge Description

Diberikan sebuah file Python beserta file terenkripsi `.enc`.

Tujuan challenge ini adalah melakukan reverse engineering terhadap program Python untuk memahami bagaimana data rahasia dibuat menjadi key, kemudian menggunakan key tersebut untuk mendekripsi file `program.enc`.

## 1. Extracting the Challenge Files

Challenge diberikan dalam bentuk archive. Karena menggunakan Windows, archive dapat diekstrak melalui PowerShell:

```powershell
Expand-Archive .\showtime.zip -DestinationPath .\showtime
cd .\showtime
dir
```

Setelah diekstrak, terdapat file Python dan file terenkripsi:

```text
showtime.py
program.enc
```

Untuk melihat ukuran `program.enc`:

```powershell
Get-Item .\program.enc
```

Hasilnya menunjukkan bahwa file berukuran **40 bytes**.

## 2. Analisis `showtime.py`

Baca source code dengan:

```powershell
Get-Content .\showtime.py
```

Bagian penting pertama adalah konstanta `_ARCHIVE`:

```python
_ARCHIVE = [54, 37, 37, 37, 43, 45, 121, 43, 36, 31, 22, 17, 75, 7, 3, 1, 26, 20, 14, 119, 124]
```

Array tersebut diproses oleh fungsi `_unseal()`:

```python
def _unseal(payload: list[int], seed: int = 0x5A) -> bytes:
    return bytes(v ^ seed ^ ((i * 3 + 7) & 0xFF) for i, v in enumerate(payload))
```

Setiap byte diproses menggunakan operasi XOR dengan formula:

```text
output[i] = payload[i] XOR seed XOR ((i * 3 + 7) & 0xFF)
```

Default seed yang digunakan adalah `0x5A`.

## 3. Recover Hidden Value dari `_ARCHIVE`

Buat `solve.py`:

```powershell
New-Item solve.py
notepad solve.py
```

Gunakan kode berikut:

```python
_ARCHIVE = [
    54, 37, 37, 37, 43, 45, 121, 43, 36, 31, 22,
    17, 75, 7, 3, 1, 26, 20, 14, 119, 124
]

def unseal(payload, seed=0x5A):
    return bytes(
        v ^ seed ^ ((i * 3 + 7) & 0xFF)
        for i, v in enumerate(payload)
    )

hidden = unseal(_ARCHIVE)

print(hidden)
print(hidden.decode())
```

Jalankan:

```powershell
python .\solve.py
```

Output:

```text
b'kuroba:magic:showtime'
kuroba:magic:showtime
```

Jadi `_ARCHIVE` menyembunyikan string:

```text
kuroba:magic:showtime
```

## 4. Analisis Fungsi `_canon()`

Source code juga memiliki fungsi:

```python
def _canon(seed: int) -> bytes:
    _ = hashlib.sha256(str(seed).encode()).digest()
    return _unseal(_ARCHIVE)
```

Ada operasi SHA-256 terhadap `seed`, tetapi hasilnya disimpan ke variabel `_` dan tidak digunakan.

Fungsi tetap mengembalikan:

```python
_unseal(_ARCHIVE)
```

Dengan demikian, nilai yang digunakan sebagai `canon` adalah:

```text
kuroba:magic:showtime
```

## 5. Menemukan Key

Di `main()` terdapat:

```python
canon = _canon(seed)
mark = hashlib.sha256(canon).hexdigest()[:16]
```

Artinya nilai `canon` diproses menggunakan SHA-256.

Hitung SHA-256 dari:

```text
kuroba:magic:showtime
```

dengan:

```python
import hashlib

canon = b"kuroba:magic:showtime"
key = hashlib.sha256(canon).digest()

print(key.hex())
```

Hasilnya:

```text
5480cd3242b09541cba7547a1eb35618f3086f9c6d5f4d1888e678b7756d0d7e
```

Digest SHA-256 tersebut berukuran 32 bytes dan menjadi key yang digunakan untuk tahap dekripsi.

## 6. Analisis `program.enc`

Untuk melihat isi hexadecimal file di Windows PowerShell:

```powershell
Format-Hex .\program.enc
```

Ciphertext yang diperoleh:

```text
00000000   1F C1 84 66 0D CB FC 35 B8 F8 27 12 71 C4 22 71
00000010   9E 6D 30 F0 0C 3B 24 7D FB B9 19 D9 11 32 6A 1B
00000020   3A F4 A1 57 2F D5 FB 3C
```

Tidak terdapat header atau signature file umum. Karena key SHA-256 memiliki panjang 32 bytes sedangkan ciphertext 40 bytes, key dapat digunakan kembali secara berulang.

## 7. Menentukan Metode Dekripsi

Metode yang digunakan adalah **repeating-key XOR**.

Rumusnya:

```text
plaintext[i] = ciphertext[i] XOR key[i % len(key)]
```

Karena key berukuran 32 bytes dan ciphertext berukuran 40 bytes, setelah byte ke-32 key kembali digunakan dari byte pertama.

## 8. Membuat Script Dekripsi

Gunakan `solve.py` berikut:

```python
import hashlib
from pathlib import Path

ARCHIVE = [
    54, 37, 37, 37, 43, 45, 121, 43, 36, 31, 22,
    17, 75, 7, 3, 1, 26, 20, 14, 119, 124
]

def unseal(payload, seed=0x5A):
    return bytes(
        v ^ seed ^ ((i * 3 + 7) & 0xFF)
        for i, v in enumerate(payload)
    )

# Recover hidden value
canon = unseal(ARCHIVE)
print("[+] Hidden value:")
print(canon.decode())

# Generate SHA-256 key
key = hashlib.sha256(canon).digest()
print("\n[+] SHA-256 key:")
print(key.hex())

# Read ciphertext
cipher = Path("program.enc").read_bytes()
print("\n[+] Ciphertext length:", len(cipher))

# Repeating-key XOR
plain = bytes(
    c ^ key[i % len(key)]
    for i, c in enumerate(cipher)
)

# Show plaintext
print("\n[+] Plaintext:")
print(plain.decode(errors="replace"))
```

Jalankan:

```powershell
python .\solve.py
```

Output plaintext:

```text
KAITO{its_showtime_ladies_and_gentlemen}
```

## 9. Verifikasi Flag

Ciphertext memiliki panjang **40 bytes** dan plaintext hasil dekripsi juga memiliki panjang yang sama. Hal ini sesuai dengan karakteristik XOR karena proses XOR tidak mengubah panjang data.

Flag yang diperoleh:

```text
KAITO{its_showtime_ladies_and_gentlemen}
```

## 10. Alur Solving

Secara keseluruhan:

```text
_ARCHIVE
    |
    v
_unseal()
    |
    v
"kuroba:magic:showtime"
    |
    v
SHA-256
    |
    v
5480cd3242b09541...
    |
    v
program.enc
    |
    v
Repeating-Key XOR
    |
    v
KAITO{its_showtime_ladies_and_gentlemen}
```

Terdapat dua tahap XOR dalam challenge:

### Tahap 1 — Recover hidden value

```python
v ^ seed ^ ((i * 3 + 7) & 0xFF)
```

Hasil:

```text
kuroba:magic:showtime
```

### Tahap 2 — Decrypt `program.enc`

```python
cipher[i] ^ key[i % len(key)]
```

dengan:

```text
key = SHA256(b"kuroba:magic:showtime")
```

## Kesimpulan

Challenge **Showtime** menggunakan kombinasi **XOR obfuscation**, **SHA-256 key derivation**, dan **repeating-key XOR**.

Kunci utama dalam solving adalah mengikuti alur data pada source code. `_ARCHIVE` tidak langsung berisi flag, melainkan harus di-unseal terlebih dahulu untuk mendapatkan:

```text
kuroba:magic:showtime
```

String tersebut kemudian di-hash menggunakan SHA-256 sehingga menghasilkan key:

```text
5480cd3242b09541cba7547a1eb35618f3086f9c6d5f4d1888e678b7756d0d7e
```

Key tersebut digunakan untuk melakukan repeating-key XOR terhadap `program.enc`, hingga akhirnya diperoleh flag:

```text
KAITO{its_showtime_ladies_and_gentlemen}
```
