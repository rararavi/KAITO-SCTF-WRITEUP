# Kaito CTF - Heist Notice

- Write-Up Author: Ravi
- Category: Stego
- Flag: `KAITO{tonights_target_is_the_moonlight_sonata}`

## Challenge Description

> Another advance notice from Kaito Kid, delivered to the Beika Art Museum before the Moonlight Sonata recital.
> The police read every word. Conan reads what is not printed in ink.
> **Author: Gojo Satoru**

## Analisis

Diberikan sebuah file `.txt` yang berisi teks biasa.

<!-- SCREENSHOT: isi notice.txt -->
![Isi notice.txt](../assets/03-heist-notice-txt.png)

Clue-nya ada di kalimat:

> *"The police read every word. Conan reads what is not printed in ink."*

Kalimat ini mengarah ke karakter **zero-width** (invisible characters) yang tersembunyi di antara teks. Karakter yang relevan adalah:

- `U+200B` (zero-width space)
- `U+200C` (zero-width non-joiner)

## Langkah Menemukan Flag

1. Buka file `notice.txt` dan deteksi karakter tak terlihat dengan script berikut:

   ```python
   with open("notice.txt", "r", encoding="utf-8") as f:
       data = f.read()

   for c in data:
       if ord(c) in (0x200B, 0x200C):
           print(hex(ord(c)))
   ```

   Output:

   ```
   0x200b 0x200c 0x200b 0x200b 0x200c 0x200b ...
   ```

2. Ubah karakter zero-width menjadi binary, `U+200B` → `0` dan `U+200C` → `1`:

   ```python
   with open("notice.txt", "r", encoding="utf-8") as f:
       data = f.read()

   hidden = ""

   for c in data:
       if c == "\u200b":
           hidden += "0"
       elif c == "\u200c":
           hidden += "1"

   print(hidden)
   ```

   Output binary:

   ```
   010010110100000101001001010101000100111101111011011101000110111101101110011010010110011101101000011101000111001101011111011101000110000101110010011001110110010101110100010111110110100101110011010111110111010001101000011001010101111101101101011011110110111101101110011011000110100101100111011010000111010001011111011100110110111101101110011000010111010001100001011111010000000000000000
   ```

3. Binary tersebut berjumlah **384 bit**; dibagi 8 menjadi **48 byte**. Pecah menjadi kelompok 8-bit lalu konversi ke karakter:

   ```python
   with open("notice.txt", "r", encoding="utf-8") as f:
       data = f.read()

   hidden = ""

   for c in data:
       if c == "\u200b":
           hidden += "0"
       elif c == "\u200c":
           hidden += "1"

   print("[+] Binary:")
   print(hidden)

   result = ""

   for i in range(0, len(hidden), 8):
       byte = hidden[i:i+8]

       if len(byte) == 8:
           result += chr(int(byte, 2))

   print("\n[+] Decoded:")
   print(result)
   ```

4. Output script menampilkan flag.

   ```
   [+] Decoded:
   KAITO{tonights_target_is_the_moonlight_sonata}
   ```

## Kesimpulan

Pesan rahasia disembunyikan menggunakan teknik steganografi zero-width characters pada teks. Karakter `U+200B` dan `U+200C` dipetakan ke bit `0` dan `1`, lalu hasilnya didecode sebagai teks ASCII.

**Flag:** `KAITO{tonights_target_is_the_moonlight_sonata}`
