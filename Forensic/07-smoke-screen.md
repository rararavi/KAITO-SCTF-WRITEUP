# Kaito CTF - Smoke Screen

- Write-Up Author: Ravi
- Category: Forensic
- Flag: `KAITO{cocoon_of_smoke_gilded_escape}`

## Challenge Description

> Kaito Kid escaped the rooftop inside a cocoon of smoke — one of five charges deployed that night.
> Four are empty misdirection. One carries what he left behind.

## Analisis

Diberikan lima file `cocoon`. Empat di antaranya hanya pengalih perhatian, satu file berisi data yang ditinggalkan Kaito Kid.

<!-- SCREENSHOT: 5 file cocoon -->
![File cocoon](../assets/07-smoke-screen-files.png)

## Langkah Menemukan Flag

1. **Periksa ukuran tiap file** untuk menemukan anomali. File yang berisi flag biasanya berukuran berbeda dari empat file kosong lainnya.

   <!-- SCREENSHOT: ukuran file, cocoon_3.bin berbeda -->
   ![Ukuran file cocoon_3.bin](../assets/07-smoke-screen-size.png)

2. **Hex dump** file yang mencurigakan (`cocoon_3.bin`) untuk melihat strukturnya.

   <!-- SCREENSHOT: hexdump cocoon_3.bin -->
   ![Hexdump cocoon_3.bin](../assets/07-smoke-screen-hexdump.png)

3. Dari hasil analisis, `cocoon_3.bin` memiliki **32 byte noise header** di awal, lalu diikuti data base64 yang terkompresi zlib.
4. Tulis script Python untuk decode:

   ```python
   import base64, zlib

   data = open('cocoon_3.bin', 'rb').read()[0x20:]  # skip 32 byte noise header
   decoded = base64.b64decode(data)
   flag = zlib.decompress(decoded)
   print(flag)
   ```

5. Jalankan script untuk mendapatkan flag.

## Kesimpulan

File `cocoon_3.bin` menyimpan payload base64 yang terkompresi zlib di belakang header noise 32 byte. Dengan menghapus header lalu melakukan base64-decode dan dekompresi, flag dapat dipulihkan.

**Flag:** `KAITO{cocoon_of_smoke_gilded_escape}`
