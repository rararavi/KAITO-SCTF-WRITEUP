# Kaito CTF - Heist Notice

> **Write-Up Author:** Ravi\
> **Category:** Stego\
> **Flag:** `KAITO{tonights_target_is_the_moonlight_sonata}`

## Challenge Description

> Another advance notice from Kaito Kid, delivered to the Beika Art
> Museum before the Moonlight Sonata recital. The police read every
> word. Conan reads what is not printed in ink.\
> **Author:** Gojo Satoru

## Analisis

Diberikan sebuah file `notice.txt` yang berisi teks biasa.

Clue utama terdapat pada kalimat:

> "The police read every word. Conan reads what is not printed in ink."

Kalimat tersebut mengarah pada kemungkinan adanya karakter yang tidak
terlihat atau **zero-width characters** yang disisipkan di antara teks.

Karakter yang relevan:

-   `U+200B` --- Zero Width Space
-   `U+200C` --- Zero Width Non-Joiner

## Langkah Menemukan Flag

### 1. Mengecek karakter Unicode tersembunyi

Buat `check.py`:

``` python
with open("notice.txt", "r", encoding="utf-8") as f:
    data = f.read()

for c in data:
    if ord(c) in (0x200B, 0x200C):
        print(hex(ord(c)))
```

Jalankan:

``` powershell
python check.py
```

Output:

``` text
0x200b
0x200c
0x200b
0x200b
0x200c
0x200b
...
```

Ini membuktikan bahwa file memiliki karakter Unicode tersembunyi.

### 2. Mengubah zero-width characters menjadi binary

Gunakan mapping:

``` text
U+200B → 0
U+200C → 1
```

Buat `extract.py`:

``` python
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

Jalankan:

``` powershell
python extract.py
```

Output berupa binary string panjang:

``` text
010010110100000101001001010101000100111101111011...
```

Payload berjumlah **384 bit**.

### 3. Membagi binary menjadi byte

Karena 1 byte = 8 bit:

``` text
384 / 8 = 48 byte
```

Contoh kelompok binary:

``` text
01001011
01000001
01001001
01010100
01001111
01111011
...
```

Contoh konversi:

``` text
01001011 → 75 → K
01000001 → 65 → A
01001001 → 73 → I
01010100 → 84 → T
01001111 → 79 → O
```

### 4. Decode binary menjadi ASCII

Script lengkap:

``` python
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

Jalankan:

``` powershell
python extract.py
```

Output:

``` text
[+] Decoded:
KAITO{tonights_target_is_the_moonlight_sonata}
```

## Kesimpulan

Challenge ini menggunakan **steganografi zero-width characters**.
Karakter `U+200B` dan `U+200C` dipetakan menjadi bit `0` dan `1`,
kemudian binary tersebut dibagi menjadi byte dan dikonversi ke ASCII.

``` text
notice.txt
    │
    ▼
U+200B / U+200C
    │
    ▼
0 / 1
    │
    ▼
Binary
    │
    ▼
8-bit bytes
    │
    ▼
ASCII
    │
    ▼
KAITO{tonights_target_is_the_moonlight_sonata}
```

**Flag:**

`KAITO{tonights_target_is_the_moonlight_sonata}`
