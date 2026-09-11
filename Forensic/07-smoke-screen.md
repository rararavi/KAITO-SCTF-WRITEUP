# Kaito CTF - Smoke Screen

- Write-Up Author: Ravi
- Category: Forensic
- Flag: `KAITO{cocoon_of_smoke_gilded_escape}`

## Challenge Description

Kaito Kid escaped the rooftop inside a **cocoon of smoke** — one of five charges deployed that night.

Four are empty misdirection. One carries what he left behind.

Author: Gojo Satoru

File yang diberikan: `smoke-screen.zip`, berisi 5 file `.bin` (`cocoon_1.bin` s/d `cocoon_5.bin`).

## Analisis

Setelah diekstrak, kelima file terlihat serupa sekilas — sama-sama file `.bin` tanpa ekstensi yang jelas. Namun deskripsi soal memberi petunjuk kuat: dari 5 "cocoon", 4 di antaranya cuma misdirection (kosong/noise), dan hanya 1 yang menyimpan data asli.

Langkah pertama adalah membandingkan ukuran file secara presisi:

```
cocoon_1.bin   132 bytes
cocoon_2.bin   132 bytes
cocoon_3.bin    92 bytes   <- beda sendiri
cocoon_4.bin   132 bytes
cocoon_5.bin   132 bytes
```

`cocoon_3.bin` langsung mencurigakan karena ukurannya berbeda dari 4 file lainnya.

Untuk memastikan, dilakukan hex dump pada semua file. File `cocoon_1.bin`, `cocoon_2.bin`, `cocoon_4.bin`, dan `cocoon_5.bin` punya pola yang sama: 32 byte pertama berupa random bytes (header dummy), lalu sisanya diisi penuh string berulang `NOISENOISENOISE...` — jelas ini cuma filler/junk data.

Sedangkan `cocoon_3.bin` berbeda: 32 byte pertama tetap random bytes, tapi setelah itu langsung diikuti teks ASCII:

```
eJzzdvQM8a9Ozk/Oz8+Lz0+LL87Nz06NT8/MSUlNiU8tTk4sSK0FAP8lDjw=
```

Prefix `eJz` adalah ciri khas base64 dari data yang dikompresi dengan **zlib** (byte pertama hasil zlib compress hampir selalu `0x78`, yang jika di-base64-kan menghasilkan awalan `eJ`). Ini mengonfirmasi bahwa `cocoon_3.bin` adalah cocoon yang menyimpan flag.

## Langkah Menemukan Flag

1. **Ekstrak ZIP** dan cek ukuran tiap file untuk menemukan anomali:

   ```
   Get-ChildItem cocoon_*.bin | Select-Object Name, Length
   ```

   Hasil menunjukkan `cocoon_3.bin` (92 byte) berbeda dari 4 file lain (132 byte).

2. **Hex dump / baca isi mentah** `cocoon_3.bin` untuk konfirmasi:

   ```python
   data = open('cocoon_3.bin', 'rb').read()
   for i in range(0, len(data), 16):
       chunk = data[i:i+16]
       hexpart = ' '.join(f'{b:02x}' for b in chunk)
       ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
       print(f'{i:06x}  {hexpart:<48}  {ascii_part}')
   ```

   32 byte pertama noise, diikuti teks ASCII berawalan `eJz` — indikasi base64 dari data zlib.

3. **Decode base64**, lalu **decompress zlib** untuk memulihkan flag:

   ```python
   import base64, zlib

   data = open('cocoon_3.bin', 'rb').read()[0x20:]  # skip 32 byte noise header
   decoded = base64.b64decode(data)
   flag = zlib.decompress(decoded)
   print(flag)
   ```

   Output:

   ```
   b'KAITO{cocoon_of_smoke_gilded_escape}'
   ```

## Kesimpulan

Dari 5 file cocoon, 4 di antaranya hanyalah random bytes yang dipadatkan dengan string berulang `NOISE` sebagai misdirection. Hanya `cocoon_3.bin` yang menyimpan data asli, dibedakan lewat ukuran filenya yang unik. Data asli tersebut disimpan sebagai base64 dari hasil kompresi zlib, sehingga cukup di-decode lalu di-decompress untuk mendapatkan flag.

**Flag:** `KAITO{cocoon_of_smoke_gilded_escape}`
