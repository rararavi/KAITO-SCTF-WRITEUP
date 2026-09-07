# Kaito CTF - He's Not Findable

- Write-Up Author: Ravi
- Category: Crypto (1000 pts)
- Flag: `Kaito{c3ntr4l_f1n1t3_curv3_hnp_l4tt1c3_c137}`

## Challenge Description

> M-Morty! *(burp)* Look at me! I locked onto Rick Prime's portal exhaust across the Curve, but the sensor's dropping the middle of his signature. Don't just stand there drooling like a dead mackerel, Morty! Sit your little ass down, we need to fix the math M-Mor\*(burp)\*..ty!
>
> `nc 31.97.37.38 1338`
> [central_finite_curve_dist.zip](attachment)

Server TCP menyediakan "portal tracker" yang mensimulasikan ECDSA pada kurva secp256k1. Setiap kali kita pilih menu `[1]`, server memberi satu signature `(r, s)` atas pesan acak, beserta `high_64` dan `low_64` — dua potongan dari nonce `k` yang dipakai untuk sign. Tujuan akhirnya adalah menandatangani pesan tetap `DIMENSION_PRIME_OMEGA_OVERRIDE_TARGET` (menu `[3]`) menggunakan private key server, `d`, yang tidak pernah diberikan secara langsung.

## Write up

**Reference:**
[HNP & Lattice Attacks on ECDSA](https://en.wikipedia.org/wiki/Hidden_number_problem) - konsep dasar Hidden Number Problem
[LLL algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) - reduksi basis lattice yang dipakai

---

## Analisis Kerentanan

Dari `server.py`, fungsi `sign_emission()` membentuk nonce sebagai:

```
k = high_64 * 2^192 + mid_128 * 2^64 + low_64
```

`high_64` dan `low_64` dibocorkan tiap response, sementara `mid_128` (128 bit di tengah, dari total 256 bit) benar-benar rahasia dan acak. Ini adalah kasus klasik **partial nonce leakage** pada ECDSA — begitu sebagian bit nonce diketahui, keamanan skema runtuh karena sisa bagian rahasia (`mid_128`) jauh lebih kecil dari orde kurva `N` (~256 bit vs 128 bit), sehingga bisa direduksi jadi **Hidden Number Problem (HNP)**.

## Penurunan Matematis

Dari persamaan signature ECDSA `s = k⁻¹(h + d·r) mod N`, substitusi `k` di atas dan isolasi `mid_128` (sebut `M`) menghasilkan hubungan linear terhadap private key `d`:

```
M = a·d + b (mod N)
a = r · s⁻¹ · 2⁻⁶⁴ mod N
b = (h · s⁻¹ − high_64·2¹⁹² − low_64) · 2⁻⁶⁴ mod N
```

dengan `M` dijamin kecil: `0 ≤ M < 2^128`. Dengan dua signature (indeks 0 dan `i`), eliminasi `d` menghasilkan:

```
M_i = u_i · M_0 + v_i (mod N)
u_i = a_i · a_0⁻¹ mod N
v_i = b_i − u_i · b_0 mod N
```

Sekarang cukup satu unknown besar (`M_0`, 128 bit) untuk menentukan semua `M_i` lainnya.

## Konstruksi Lattice & Serangan LLL

Dibentuk basis lattice berdimensi `m+1` (m = jumlah signature yang dipakai):

- `m-1` baris `N·e_j` (representasi reduksi modulo)
- baris `(u_1, …, u_{m-1}, 1, 0)`
- baris `(v_1, …, v_{m-1}, 0, 1)`

Vektor `(M_1, …, M_{m-1}, M_0, 1)` adalah **vektor pendek** yang sungguhan ada di dalam lattice ini (semua entri `< 2^128`, jauh lebih kecil dibanding baris-baris berskala `N` ~2^256), sehingga algoritma reduksi basis **LLL** bisa menemukannya secara langsung tanpa brute force.

*Catatan debugging (poin menarik untuk writeup):* draft awal solve script keliru mengalikan kolom penanda `M_0` dengan `2^128`, sehingga vektor target yang dicari jadi berorde `2^256` — lebih besar dari vector basis lattice lain, membuat LLL gagal menemukannya. Perbaikannya cukup mengganti skala kolom itu jadi `1`.

## Recovery Key & Forge Signature

Begitu `M_0` ditemukan dari hasil reduksi lattice: `d = (M_0 − b_0) · a_0⁻¹ mod N`, diverifikasi dengan `d·G == pubkey_target`. Dalam praktiknya cukup **5 signature** (m=5) untuk berhasil, proses reduksi ~25 detik.

Dengan `d` di tangan, forge signature ECDSA standar untuk pesan target: pilih `k` acak, `r = (k·G).x mod N`, `s = k⁻¹(h + d·r) mod N`. Kirim ke menu [3] server → verifikasi signature server cocok → `ACCESS GRANTED` → flag keluar.

## Langkah Eksploitasi (Reproduksi)

1. **Ekstrak & baca source.** Extract `central_finite_curve_dist.zip`, buka `curve.py`, `server.py`, `intro.txt`. Catat parameter kurva (`P`, `N`, `G`) dan alur menu server: `[1]` minta signature bocor, `[2]` lihat pubkey target, `[3]` submit signature buat auth sebagai Rick Prime.
2. **Konfirmasi kerentanan** seperti dijelaskan di atas: `high_64` dan `low_64` selalu dibocorkan tiap signature, hanya `mid_128` yang rahasia → reduksi ke HNP.
3. **Tulis script solver** (`fixed_solve.py`) yang:
   - Konek ke server via socket, selesaikan proof-of-work.
   - Kumpulkan ±20 signature lewat menu `[1]`, ambil `r, s, high_64, low_64`, dan hash pesan.
   - Hitung `a_i, b_i` untuk tiap signature, bentuk lattice seperti di atas, jalankan LLL (implementasi manual pakai `Fraction` untuk presisi eksak).
   - Cari kombinasi `d` yang valid (`d·G == pubkey`) mulai dari `m=5` signature.
4. **Uji self-test offline dulu** (`python fixed_solve.py test`) — generate signature palsu dengan `d` acak, pastikan solver berhasil recover `d` sebelum dipakai ke server sungguhan. Ini penting karena percobaan pertama (skala kolom lattice salah) gagal di tahap ini, baru ketahuan bug-nya sebelum buang jatah query ke server.
5. **Jalankan ke server target:**
   ```
   python fixed_solve.py
   ```
6. **Hasil run (log asli):**
   ```
   [*] PoW prefix: 8b0b46e92742
   [*] Target pubkey: 0xd5f06d21a17fe20caa4ca746596a036f180ea9b1e1ab2f5d7489632f55c68b81 ...
   [*] signature 1/20 ... [*] signature 20/20
   [*] lattice m=5 : found (25.3s)
   [+] PRIVATE KEY d = 0x8acecf81a84c58436c79984e8d2ec6387c1ab5a83dda3eb842a920e7fe55dfc2
   [+] forged r = 0x6e696c91ad8bec19beb94556a5863c01dc5ece4b402673157ffa09a0ab5a8643
   [+] forged s = 0x4faa61fcb9f1146aa8d027d8a973c69e6b2462e6a65b6980f05d1fa01bf9e8d2
   [+] ACCESS GRANTED! Rick Prime portal signature confirmed!
   [+] FLAG: Kaito{c3ntr4l_f1n1t3_curv3_hnp_l4tt1c3_c137}
   ```
7. **Submit flag** ke platform CTF.

## Kesimpulan

Root cause: kebocoran sebagian bit nonce ECDSA (bukan nonce penuh yang bocor, cukup MSB+LSB) sudah cukup untuk membuka celah HNP yang solvable via lattice reduction — menegaskan prinsip keamanan ECDSA bahwa **nonce harus 100% rahasia dan unik**, tidak boleh bocor sebagian sekalipun.

## Lampiran: Full Solver Script (`fixed_solve.py`)

```python
import socket, hashlib, re, time, random, sys, math, secrets
from fractions import Fraction

HOST, PORT = "31.97.37.38", 1338
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def padd(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        l = 3 * x1 * x1 % P * pow(2 * y1, -1, P) % P
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    y3 = (l * (x1 - x3) - y1) % P
    return (x3, y3)

def pmul(k, pt):
    k %= N
    res, cur = None, pt
    while k > 0:
        if k & 1: res = padd(res, cur)
        cur = padd(cur, cur)
        k >>= 1
    return res

G = (GX, GY)

def lll(B, delta=Fraction(99, 100)):
    B = [[Fraction(x) for x in row] for row in B]
    n = len(B)

    def gs():
        Bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            w = list(B[i])
            for j in range(i):
                dj = sum(x * x for x in Bs[j])
                if dj == 0: continue
                c = sum(a * b for a, b in zip(w, Bs[j])) / dj
                mu[i][j] = c
                w = [a - c * b for a, b in zip(w, Bs[j])]
            Bs.append(w)
        return Bs, mu

    while True:
        changed = False
        for i in range(1, n):
            Bs, mu = gs()
            for j in range(i - 1, -1, -1):
                q = round(mu[i][j])
                if q:
                    B[i] = [B[i][k] - q * B[j][k] for k in range(len(B[i]))]
                    changed = True
        Bs, mu = gs()
        swapped = False
        for i in range(1, n):
            ni = sum(x * x for x in Bs[i])
            nprev = sum(x * x for x in Bs[i - 1])
            if ni < (delta - mu[i][i - 1] ** 2) * nprev:
                B[i], B[i - 1] = B[i - 1], B[i]
                swapped = True
                break
        if not changed and not swapped:
            return [[int(x) for x in row] for row in B]


def recover_key(sigs, Q):
    inv2_64 = pow(1 << 64, -1, N)
    a, b = [], []
    for (r, s, H, L, h) in sigs:
        si = pow(s, -1, N)
        a.append(r * si % N * inv2_64 % N)
        b.append((h * si - (H << 192) - L) % N * inv2_64 % N)

    m = len(sigs)
    a0i = pow(a[0], -1, N)
    u = [a[i] * a0i % N for i in range(1, m)]
    v = [(b[i] - u[i - 1] * b[0]) % N for i in range(1, m)]

    rows = []
    for j in range(m - 1):
        row = [0] * (m + 1)
        row[j] = N
        rows.append(row)
    rows.append(u + [1, 0])
    rows.append(v + [0, 1])

    red = lll(rows)
    for w in red:
        for sgn in (1, -1):
            w2 = [sgn * x for x in w]
            if w2[m] != 1:
                continue
            m0 = w2[m - 1]
            if not (0 <= m0 < (1 << 128)):
                continue
            d = (m0 - b[0]) * a0i % N
            if pmul(d, G) == Q:
                return d
    return None


def selftest():
    d = random.randrange(1, N)
    Q = pmul(d, G)
    sigs = []
    for _ in range(20):
        msg = "dimension_prime_signal_" + secrets.token_hex(6)
        h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % N
        H, M, L = random.getrandbits(64), random.getrandbits(128), random.getrandbits(64)
        k = (H << 192) + (M << 64) + L
        if k % N == 0: k = 1
        R = pmul(k, G)
        r = R[0] % N
        s = pow(k, -1, N) * (h + d * r) % N
        sigs.append((r, s, H, L, h))
    ok = True
    for m in (5, 6, 7):
        t0 = time.time()
        dd = recover_key(sigs[:m], Q)
        dt = time.time() - t0
        print("[test] m=%2d : %s (%.2fs)" % (m, "OK" if dd == d else "FAIL", dt), flush=True)
        ok &= dd == d
    print("[test] RESULT:", "ALL OK" if ok else "FAILED", flush=True)
    return ok


class Tube:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=30)
        self.buf = b""

    def recv_until(self, pat, timeout=90):
        self.s.settimeout(timeout)
        pb = pat.encode(); start = time.time()
        while pb not in self.buf:
            if time.time() - start > timeout:
                raise TimeoutError("waiting %r, tail=%r" % (pat, self.buf[-200:]))
            c = self.s.recv(8192)
            if not c: raise ConnectionError("closed, tail=%r" % self.buf[-200:])
            self.buf += c
        i = self.buf.index(pb) + len(pb)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out.decode(errors="replace")

    def drain(self, secs=6):
        self.s.settimeout(secs)
        try:
            while True:
                c = self.s.recv(8192)
                if not c: break
                self.buf += c
        except (socket.timeout, ConnectionError):
            pass
        out, self.buf = self.buf, b""
        return out.decode(errors="replace")

    def send(self, line):
        self.s.sendall((line + "\n").encode())


def pow_solve(prefix, target="0000"):
    pre = prefix.encode(); i = 0
    while True:
        if hashlib.sha256(pre + str(i).encode()).hexdigest().startswith(target):
            return i
        i += 1


def main():
    t = Tube()
    banner = t.recv_until("PoW answer > ")
    prefix = re.search(r"Challenge Prefix: ([0-9a-f]+)", banner).group(1)
    print("[*] PoW prefix:", prefix, flush=True)
    ans = pow_solve(prefix)
    t.send(str(ans))
    menu = t.recv_until("> ")
    txt = banner + menu
    qx = int(re.search(r"Target Public Key \(X\): (0x[0-9a-fA-F]+)", txt).group(1), 16)
    qy = int(re.search(r"Target Public Key \(Y\): (0x[0-9a-fA-F]+)", txt).group(1), 16)
    Q = (qx, qy)
    print("[*] Target pubkey:", hex(qx), hex(qy), flush=True)

    NQ = 20
    sigs = []
    for q in range(NQ):
        t.send("1")
        blk = t.recv_until("> ")
        r = int(re.search(r"r:\s+(0x[0-9a-f]+)", blk).group(1), 16)
        s = int(re.search(r"s:\s+(0x[0-9a-f]+)", blk).group(1), 16)
        hi = int(re.search(r"high_64:\s+(0x[0-9a-f]+)", blk).group(1), 16)
        lo = int(re.search(r"low_64:\s+(0x[0-9a-f]+)", blk).group(1), 16)
        msg = re.search(r"Message:\s+(\S+)", blk).group(1)
        h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % N
        if r and s:
            sigs.append((r, s, hi, lo, h))
        print("[*] signature %d/%d" % (q + 1, NQ), flush=True)

    d = None
    for m in (5, 6, 7):
        t0 = time.time()
        cand = recover_key(sigs[:m], Q)
        print("[*] lattice m=%-2d: %s (%.1fs)" % (m, "found" if cand else "fail", time.time() - t0), flush=True)
        if cand:
            d = cand
            break
    if d is None:
        print("[-] key recovery failed")
        sys.exit(1)
    print("[+] PRIVATE KEY d =", hex(d), flush=True)
    assert pmul(d, G) == Q

    target_msg = "DIMENSION_PRIME_OMEGA_OVERRIDE_TARGET"
    h_t = int(hashlib.sha256(target_msg.encode()).hexdigest(), 16) % N
    while True:
        k = random.randrange(1, N)
        R = pmul(k, G)
        if R is None: continue
        r_t = R[0] % N
        if r_t == 0: continue
        s_t = pow(k, -1, N) * (h_t + d * r_t) % N
        if s_t: break
    print("[+] forged r =", hex(r_t), flush=True)
    print("[+] forged s =", hex(s_t), flush=True)

    t.send("3")
    t.recv_until("Signature r (hex) > ")
    t.send(hex(r_t))
    t.recv_until("Signature s (hex) > ")
    t.send(hex(s_t))
    final = t.drain(8)
    print(final, flush=True)
    fl = re.search(r"FLAG:\s*(\S+)", final)
    print("[+] FLAG:", fl.group(1) if fl else "not found", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        sys.exit(0 if selftest() else 1)
    main()
```
