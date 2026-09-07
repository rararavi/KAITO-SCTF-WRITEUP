# Kaito CTF - The Omega Trigger

- Write-Up Author: Ravi
- Category: Crypto
- Flag: `Kaito{0m3g4_d3v1c3_matsumoto_imai_patarin_differential}`

## Challenge Description

> M-Morty! *(burp)* Look at me! We—we jumped through his portal signature, but where the hell are we?! The doors just slammed shut! It's a localized gravity cage. He knew we were tracking him through the Curve.
>
> *A holographic projection of Rick Prime flickers to life:* "Look at you, C-137. I left the master trigger to the Omega Device right here. To arm it, you just have to solve the system. But let's be honest, your math is as pathetic as your emotions. Good luck, sad boy. You're gonna need infinity."
>
> `nc 31.97.37.38 1339`
> [the_omega_trigger_dist.zip](attachment)

Server TCP menyediakan sebuah "Omega Console" yang mengimplementasikan skema **multivariate public-key cryptosystem** ala Matsumoto-Imai. Kita diberi ciphertext target `Y`, boleh meminta server mengevaluasi fungsi enkripsi publik `P(x')` untuk `x'` bebas (maksimal 1200 kali lewat menu `[1]`), dan menang dengan mengirimkan `x` rahasia yang cocok dengan `Y` lewat menu `[3]`.

## Write up

**Reference:**
[Matsumoto-Imai cryptosystem](https://en.wikipedia.org/wiki/Multivariate_cryptography) - skema C\* dan konsep central map
Jacques Patarin, *"Cryptanalysis of the Matsumoto and Imai Public Key Scheme of Eurocrypt '88"* (1995) - serangan linearization equations

---

## Analisis Kerentanan

Dari `server.py` dalam dist, alur enkripsi publiknya:

```
y = L1( F( L2(x) ) )
```

- `L1`, `L2` — matriks acak invertible 31×31 bit (linear map penyamar).
- `F(X) = X · X² = X³` — *central map*, dihitung di dalam field `GF(2^31)`.
- `x`, `y` — vektor bit 31-dimensi (plaintext rahasia & ciphertext publik).

Ini adalah skema **Matsumoto-Imai (C\*)**: central map berupa perkalian elemen dengan Frobenius-nya sendiri (`X^{1+2^θ}`, di sini `θ=1`). Karena `2^31 − 1` adalah bilangan prima Mersenne, `gcd(3, 2^31−1) = 1`, sehingga `F` adalah **bijeksi** — solusi `x` untuk `y` tertentu **unik**, bukan sekadar tebakan.

Kelemahan klasik skema ini (Patarin, 1995): meskipun `L1` dan `L2` menyamarkan hubungan `x` dan `y`, sifat aljabar dari `X³` tetap menyisakan **relasi bilinear** yang berlaku untuk *semua* pasangan `(x, y)` valid, tidak peduli seperti apa `L1`/`L2`-nya:

```
Σ aᵢⱼ · xᵢ · yⱼ  +  Σ bᵢ · xᵢ  +  Σ cⱼ · yⱼ  +  d  =  0   (mod 2)
```

Relasi inilah yang disebut **linearization equations**, dan bisa ditemukan murni lewat pasangan `(x,y)` hasil query — tanpa perlu tahu isi `L1`/`L2` sama sekali.

## Penurunan Matematis

Untuk `DIM = 31`, jumlah monomial yang mungkin dalam relasi di atas adalah:

```
DIM² (suku aᵢⱼxᵢyⱼ) + DIM (suku bᵢxᵢ) + DIM (suku cⱼyⱼ) + 1 (konstanta d) = 1024
```

Setiap pasangan `(x, y)` hasil query oracle memberi **satu batasan linear** atas 1024 koefisien tersebut (koefisien mana yang boleh nonzero agar relasi tetap 0 untuk semua data). Dengan mengumpulkan cukup banyak pasangan (>1024, diambil ~1144 untuk buffer aman) dan mencari **null space**-nya lewat eliminasi Gauss di GF(2), didapat basis relasi yang benar-benar berlaku universal — pada percobaan ini null space berdimensi 62.

Langkah kuncinya: karena `y` **target** sudah kita ketahui dari awal, substitusi `y` itu ke setiap relasi mengubahnya dari persamaan bilinear (2 variabel tak diketahui) menjadi **persamaan linear murni** dalam 31 bit `x` rahasia:

```
Σᵢ ( Σⱼ aᵢⱼ·yⱼ + bᵢ ) · xᵢ  =  Σⱼ cⱼ·yⱼ + d      (mod 2)
```

62 relasi → 62 persamaan linear untuk 31 unknown `x`. Diselesaikan lewat eliminasi Gauss lagi, didapat rank 30/31 — hanya **1 bit bebas** yang tersisa (ambiguitas kecil, wajar untuk skema ini), sehingga tinggal 2 kandidat `x` yang mungkin.

## Verifikasi & Recovery

Kedua kandidat `x` diuji langsung ke oracle server (`P(x_candidate)` dibandingkan dengan target `Y`) — cukup 1-2 query tambahan, jauh di bawah sisa budget. Kandidat yang cocok itulah `x` rahasia yang dicari, langsung disubmit lewat menu `[3]`.

Total query yang terpakai: **1144 (kumpul data) + 2 (verifikasi) = 1146**, masih di bawah limit 1200.

## Langkah Eksploitasi (Reproduksi)

1. **Ekstrak & baca source.** Extract `the_omega_trigger_dist.zip`, baca `server.py` dan `Dockerfile`. Catat: `DIM=31`, central map `F(X)=X³` di `GF(2^31)`, menu `[1]` evaluate, `[2]` lihat target, `[3]` submit `x`, budget 1200 query.
2. **Identifikasi skema** sebagai Matsumoto-Imai (C\*) dan kenali celahnya sebagai serangan linearization equations Patarin.
3. **Uji coba offline dulu.** Salin fungsi kripto inti dari `server.py` (central map, matrix generator), simulasikan oracle secara lokal, dan verifikasi seluruh pipeline serangan (kumpul sampel → null space GF(2) → substitusi target → solve sistem linear → brute-force bit bebas) berhasil menemukan `x` rahasia sebelum menyentuh server sungguhan.
4. **Tulis network client** (`solve.py`) untuk konek ke server dan menjalankan pipeline yang sama secara live.
5. **Kendala infrastruktur** yang ditemukan saat run pertama kali (dan solusinya):
   - Server live ternyata dibungkus **proof-of-work gate** (cari `i` agar `sha256(prefix+i)` diawali `0000`) yang tidak ada di `server.py` dalam zip. → ditambahkan solver PoW brute-force sederhana (<1 detik).
   - Teks banner & menu live memakai tema "Omega Device" yang berbeda persis dari string di `server.py` dist (contoh: `"Target Ciphertext Y : 0x..."` — ada spasi sebelum titik dua — bukan `"Target Ciphertext Y: 0x..."`). Parsing berbasis *exact string match* jadi gagal terus (`TimeoutError`). → diganti jadi parsing berbasis **regex** yang mencari pola umum `0x[0-9a-fA-F]+` dan penanda giliran `\n>`, sehingga tidak bergantung pada teks tema spesifik.
6. **Jalankan ke server target:**
   ```
   python solve.py
   ```
7. **Hasil run (log asli):**
   ```
   === solve.py v4 (robust regex parsing for live server) ===
   Solving PoW: prefix=379221c3dce4 target_prefix=0000
   PoW solved: i=691 (took 0.00s)
   [+] Target Ciphertext Y : 0x6c94637e
   Target Y = 0x6c94637e
   collected 1144/1144  elapsed=9.6s
   null space dim: 62
   rank: 30 free_vars: [23]
   2 candidate(s) to verify
   candidate failed: 0x0
   VERIFIED candidate: 0x83224f
   [+] OMEGA DEVICE ARMED! DELETION MATRIX INVERTED!
   [+] FLAG: Kaito{0m3g4_d3v1c3_matsumoto_imai_patarin_differential}
   ```
8. **Submit flag** ke platform CTF.

## Kesimpulan

Root cause: central map `F(X) = X³` pada skema Matsumoto-Imai punya **struktur aljabar khusus** (perkalian elemen dengan pangkat Frobenius-nya) yang tidak bisa disembunyikan sepenuhnya oleh transformasi linear acak `L1`/`L2`. Relasi bilinear antara bit plaintext dan ciphertext tetap bisa ditemukan murni dari pasangan input-output (chosen plaintext), lalu digunakan untuk mengubah masalah "invers fungsi nonlinear" menjadi sekadar **sistem persamaan linear** begitu ciphertext target diketahui — inilah alasan skema C\* murni sudah dianggap tidak aman sejak 1995 dan hanya dipakai sebagai komponen skema yang lebih kompleks (mis. HFE, Sflash dengan modifikasi tambahan).

Pelajaran tambahan dari sisi eksploitasi praktis: **jangan asumsikan file dist = server live 100% identik** — proof-of-work gate dan teks tema tambahan sering disisipkan di layer infrastruktur deployment tanpa mengubah source code inti yang dibagikan, jadi parser sebaiknya dibuat robust (regex pada pola data, bukan exact string match pada teks dekoratif).

## Lampiran: Full Solver Script (`solve.py`)

```python
import socket
import re
import random
import itertools
import hashlib
import time

HOST = "31.97.37.38"
PORT = 1339
DIM = 31
NUM_MONOMIALS = DIM * DIM + DIM + DIM + 1  # 1024
NUM_SAMPLES = NUM_MONOMIALS + 120  # buffer above the 1024 needed
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")

random.seed()


def int_to_bits(val, dim):
    return [(val >> i) & 1 for i in range(dim)]


def monomial_row(x_bits, y_bits, N=DIM):
    row = 0
    for i in range(N):
        if x_bits[i]:
            base = i * N
            for j in range(N):
                if y_bits[j]:
                    row |= (1 << (base + j))
    idxB = N * N
    for i in range(N):
        if x_bits[i]:
            row |= (1 << (idxB + i))
    idxC = idxB + N
    for j in range(N):
        if y_bits[j]:
            row |= (1 << (idxC + j))
    idxD = idxC + N
    row |= (1 << idxD)
    return row


def nullspace_gf2(rows, num_cols):
    pivots = {}
    for r in rows:
        cur = r
        while cur:
            hb = cur.bit_length() - 1
            if hb not in pivots:
                pivots[hb] = cur
                break
            cur ^= pivots[hb]
    pivot_cols_set = set(pivots.keys())
    sorted_pivot_cols = sorted(pivots.keys(), reverse=True)
    for col in sorted_pivot_cols:
        row = pivots[col]
        for other_col in sorted_pivot_cols:
            if other_col == col:
                continue
            other_row = pivots[other_col]
            if (other_row >> col) & 1:
                pivots[other_col] = other_row ^ row
    free_cols = [c for c in range(num_cols) if c not in pivot_cols_set]
    basis = []
    for fc in free_cols:
        v = (1 << fc)
        for col, row in pivots.items():
            if (row >> fc) & 1:
                v |= (1 << col)
        basis.append(v)
    return basis


def relation_to_x_equation(relV, y_bits, N=DIM):
    coef = [0] * N
    idxB = N * N
    idxC = N * N + N
    idxD = N * N + 2 * N
    for i in range(N):
        c = (relV >> (idxB + i)) & 1
        base = i * N
        for j in range(N):
            if (relV >> (base + j)) & 1 and y_bits[j]:
                c ^= 1
        coef[i] = c
    const = (relV >> idxD) & 1
    for j in range(N):
        if (relV >> (idxC + j)) & 1 and y_bits[j]:
            const ^= 1
    return coef, const


def solve_gf2(eqs, rhs, n):
    aug = []
    for row, b in zip(eqs, rhs):
        val = 0
        for i in range(n):
            if row[i]:
                val |= (1 << i)
        if b:
            val |= (1 << n)
        aug.append(val)
    pivots = {}
    for r in aug:
        cur = r
        while True:
            lowbits = cur & ((1 << n) - 1)
            if lowbits == 0:
                if (cur >> n) & 1:
                    raise ValueError("Inconsistent system")
                break
            col = (lowbits & -lowbits).bit_length() - 1
            if col not in pivots:
                pivots[col] = cur
                break
            cur ^= pivots[col]
    cols = sorted(pivots.keys())
    for col in cols:
        row = pivots[col]
        for other in cols:
            if other == col:
                continue
            orow = pivots[other]
            if (orow >> col) & 1:
                pivots[other] = orow ^ row
    x = [0] * n
    for col, row in pivots.items():
        x[col] = (row >> n) & 1
    free_vars = [c for c in range(n) if c not in pivots]
    return x, cols, free_vars, pivots


def solve_pow(prefix, target):
    i = 0
    while True:
        h = hashlib.sha256((prefix + str(i)).encode()).hexdigest()
        if h.startswith(target):
            return i
        i += 1


class Client:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=30)
        self.sock.settimeout(5)
        self.buf = b""

    def read_until(self, marker, max_wait=180):
        marker = marker.encode() if isinstance(marker, str) else marker
        start = time.time()
        while marker not in self.buf:
            if time.time() - start > max_wait:
                raise TimeoutError(
                    f"Gave up waiting for {marker!r} after {max_wait}s. "
                    f"Buffer so far:\n{self.buf.decode(errors='replace')}"
                )
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError(
                    f"Server closed connection while waiting for {marker!r}. "
                    f"Buffer so far:\n{self.buf.decode(errors='replace')}"
                )
            self.buf += chunk
        idx = self.buf.find(marker)
        data = self.buf[: idx + len(marker)]
        self.buf = self.buf[idx + len(marker):]
        return data

    def send(self, s):
        self.sock.sendall(s.encode())


def main():
    c = Client(HOST, PORT)

    pow_raw = c.read_until("PoW answer >")
    pow_text = pow_raw.decode(errors="replace")
    m = re.search(
        r"Challenge Prefix:\s*(\S+)\s*\|\s*Target:\s*startswith\('([0-9a-fA-F]+)'\)",
        pow_text,
    )
    prefix, target = m.group(1), m.group(2)
    print(f"Solving PoW: prefix={prefix} target_prefix={target}")
    ans = solve_pow(prefix, target)
    print(f"PoW solved: i={ans}")
    c.send(str(ans) + "\n")

    init_raw = c.read_until("\n>")
    init_text = init_raw.decode(errors="replace")
    hexes = HEX_RE.findall(init_text)
    target_val = int(hexes[0], 16)
    target_bits = int_to_bits(target_val, DIM)
    print(f"Target Y = {hex(target_val)}")

    samples = []
    t0 = time.time()
    BATCH = 50
    total = 0
    while total < NUM_SAMPLES:
        n = min(BATCH, NUM_SAMPLES - total)
        xs = [random.getrandbits(DIM) for _ in range(n)]
        payload = ""
        for xv in xs:
            payload += "1\n" + format(xv, "x") + "\n"
        c.send(payload)
        for xv in xs:
            chunk_text = c.read_until("\n>").decode(errors="replace")
            hx = HEX_RE.findall(chunk_text)
            yv = int(hx[0], 16)
            samples.append((xv, yv))
        total += n
        print(f"collected {total}/{NUM_SAMPLES}  elapsed={time.time()-t0:.1f}s")

    rows = []
    for xv, yv in samples:
        xb = int_to_bits(xv, DIM)
        yb = int_to_bits(yv, DIM)
        rows.append(monomial_row(xb, yb))

    basis = nullspace_gf2(rows, NUM_MONOMIALS)
    print("null space dim:", len(basis))

    eqs, rhs = [], []
    for relV in basis:
        coef, const = relation_to_x_equation(relV, target_bits)
        eqs.append(coef)
        rhs.append(const)

    x_particular, pivot_cols, free_vars, pivots = solve_gf2(eqs, rhs, DIM)
    print("rank:", len(pivot_cols), "free_vars:", free_vars)

    null_basis = []
    for f in free_vars:
        v = [0] * DIM
        v[f] = 1
        for col in pivot_cols:
            row = pivots[col]
            v[col] = (row >> f) & 1
        null_basis.append(v)

    candidates = []
    for combo in itertools.product([0, 1], repeat=len(free_vars)):
        cand = x_particular[:]
        for bit, nb in zip(combo, null_basis):
            if bit:
                cand = [a ^ b for a, b in zip(cand, nb)]
        candidates.append(cand)

    found_val = None
    for cand in candidates:
        cand_val = 0
        for i, b in enumerate(cand):
            if b:
                cand_val |= (1 << i)
        c.send("1\n" + format(cand_val, "x") + "\n")
        chunk_text = c.read_until("\n>").decode(errors="replace")
        hx = HEX_RE.findall(chunk_text)
        yv = int(hx[0], 16) if hx else None
        if yv == target_val:
            found_val = cand_val
            print("VERIFIED candidate:", hex(cand_val))
            break
        else:
            print("candidate failed:", hex(cand_val))

    c.send("3\n" + format(found_val, "x") + "\n")
    time.sleep(1.5)
    remaining = b""
    try:
        while True:
            chunk = c.sock.recv(65536)
            if not chunk:
                break
            remaining += chunk
    except socket.timeout:
        pass
    print(remaining.decode(errors="replace"))


if __name__ == "__main__":
    main()
```
