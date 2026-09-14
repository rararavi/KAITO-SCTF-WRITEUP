# Kaito CTF - Teleprinter TP-52

- Write-Up Author: reybong
- Category: Crypto
- Flag: `Kaito{QAJRCEBTHUZNLKOVYMIWXPDFGS_PBTUXACNHVSKWEMRDGJOQLIFYZ_IOWKZNVDALUFPQYSJTBCMEGRXH_AQ_BH_CX_DZ_ES_FR_GV_IP_JT_KL_MO_NU_WY}`

## Challenge Description

> We intercepted communications from an experimental electromechanical teleprinter unit (Model TP-52). You know what to do.

**Target File:** `teleprinter.py`, `teleprinter.log`

## Analisis

`teleprinter.py` merepresentasikan mesin enkripsi bergaya Enigma dengan matriks permutasi NumPy (`DrumWheel`, `SymmetricBank`, `TeleprinterCipher`). Empat komponen wiring dirahasiakan (3 rotor `W1, W2, W3` + 1 reflektor/stator `Stator`), yang susunannya menjadi isi flag.

Dalam `teleprinter.log`, terdapat 1000 pesan (10 blok x 100 pesan) berpanjang 6 karakter beserta rotor order, plugboard, dan setting.

Kerentanan utama:
1. Pesan hanya 6 karakter, sehingga fast rotor bergerak sedangkan mid/slow rotor tetap.
2. Formulasi permutasi untuk dua posisi berurutan menghapus bagian mid/slow rotor dan stator:
   $H_{t+1} = K \cdot H_t \cdot K^{-1}$, dengan $K = W^{-1} C W$.
3. 5 relasi dari 6 karakter secara unik mengunci $K$, sehingga 26-siklus dari $K$ langsung merekonstruksi matriks wiring $W$ (menyisakan 26 kemungkinan rotasi per rotor).
4. Bruteforce $26^3 = 17.576$ kemungkinan rotasi dalam kurun waktu singkat mengunci seluruh permutasi wiring rahasia dan stator.

## Langkah Menemukan Flag

1. Parse log untuk mengekstrak 10 blok setting dan 100 pasang plaintext/ciphertext per blok.
2. Hapus efek plugboard ($S$) pada setiap posisi.
3. Selesaikan persamaan konjugat $H_{t+1} = K \cdot H_t \cdot K^{-1}$ untuk menentukan siklus rotor $K$.
4. Lakukan pencarian rotasi pada $26^3$ ruang kunci untuk merekonstruksi string wiring `W1`, `W2`, `W3` dan `stator`.

Script otomatisasi eksploitasi (`solver.py`):

```python
import numpy as np

# Core logic to solve conjugator relations H_{t+1} = K * H_t * K^-1
def solve_conjugator(relations, N=26):
    out = []
    for seed in range(N):
        g, stack, ok = {0: seed}, [0], True
        while stack and ok:
            x = stack.pop()
            for a, b in relations:
                nx, ny = a[x], b[g[x]]
                if nx in g:
                    if g[nx] != ny:
                        ok = False; break
                else:
                    g[nx] = ny; stack.append(nx)
        if ok and len(g) == N and len(set(g.values())) == N:
            out.append(tuple(g[i] for i in range(N)))
    return out

# Execute full solve pipeline against teleprinter.log...
# (Outputting recovered wiring strings for W1, W2, W3, and stator)
```

Jalankan eksploitasi dengan perintah:
```bash
python solver.py
```

**Flag:** `Kaito{QAJRCEBTHUZNLKOVYMIWXPDFGS_PBTUXACNHVSKWEMRDGJOQLIFYZ_IOWKZNVDALUFPQYSJTBCMEGRXH_AQ_BH_CX_DZ_ES_FR_GV_IP_JT_KL_MO_NU_WY}`
