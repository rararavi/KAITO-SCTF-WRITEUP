#!/usr/bin/env python3
"""
Microverse Battery - solve.py

Attack chain
------------
The challenge uses:

    k_i = SHA256(str(counter))
    counter <- counter + 1 + SHA256(message) mod 2^256

for ECDSA signing.  Key exchange uses the next k_i as an ECDH scalar.

We exploit the fact that the counter transition is controllable by choosing
messages.

First find a subset S such that:

    sum(1 + SHA256(m)) == 2^255 (mod 2^256)

If we send every message in S twice, the total transition is:

    2 * 2^255 == 0 (mod 2^256)

so the hidden counter returns to exactly the same state.

We perform two such cycles.  The second cycle is a rotation of the first,
so its first signature is on a different message but is produced from the
same counter/nonce.

Then:

    k = (z1-z2)/(s1-s2) mod N
    x = (s1*k-z1)/r1 mod N

recovers the ECDSA private key x.

After the second cycle the counter is again at its original state, therefore
the key-exchange operation uses exactly the same k.  We can compute k*Q,
derive the AES key/IV from S.x, and decrypt the flag.

The subset-sum phase uses a standard 0/1 lattice embedding and fpylll.
"""

import argparse
import hashlib
import json
import re
import socket
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ---------------------------------------------------------------------------
# Challenge constants
# ---------------------------------------------------------------------------

M = 1 << 256
TARGET = 1 << 255
MAX_ACTIONS = 670

# NIST P-256 parameters from server.py
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


# ---------------------------------------------------------------------------
# Hash / arithmetic helpers
# ---------------------------------------------------------------------------

def sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def h_message(msg: str) -> int:
    return sha256_int(msg.encode())


def increment(msg: str) -> int:
    # Exact server transition:
    #   cnt = (cnt + 1 + h(msg)) % 2^256
    return (h_message(msg) + 1) & (M - 1)


def inv(a: int, mod: int) -> int:
    return pow(a % mod, -1, mod)


# ---------------------------------------------------------------------------
# P-256 implementation matching server.py
# ---------------------------------------------------------------------------

def p256_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = ((3 * x1 * x1 + A) * inv(2 * y1, P)) % P
    else:
        lam = ((y2 - y1) * inv(x2 - x1, P)) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def p256_mul(k: int, point=(GX, GY)):
    # Matches Point.__rmul__: scalar is reduced modulo N.
    k %= N

    result = None
    current = point

    while k:
        if k & 1:
            result = p256_add(result, current)
        current = p256_add(current, current)
        k >>= 1

    return result


# ---------------------------------------------------------------------------
# Message generation
# ---------------------------------------------------------------------------

def make_messages(count: int, prefix: str):
    return [f"{prefix}{i:04d}" for i in range(count)]


def verify_subset(messages, indices):
    total = sum(increment(messages[i]) for i in indices) & (M - 1)
    return total == TARGET


# ---------------------------------------------------------------------------
# Lattice subset-sum solver
# ---------------------------------------------------------------------------

def build_lattice(messages, target=TARGET):
    """
    Build the standard subset-sum embedding.

    Dimension = n + 2

        row i     = [e_i | a_i | 0]
        row n     = [0   | M   | 0]
        row n + 1 = [0   | -t  | 1]

    A lattice vector generated as

        sum(x_i row_i) + q row_n + row_(n+1)

    is

        [x_0,...,x_(n-1), sum(x_i*a_i)+qM-t, 1]

    so an exact subset-sum solution appears as a short vector with:

        x_i in {0,1}
        middle coordinate == 0
        final coordinate == 1
    """
    try:
        from fpylll import IntegerMatrix
    except ImportError as exc:
        raise RuntimeError(
            "fpylll is required.\n"
            "Install it with:\n"
            "    pip install fpylll cysignals\n"
        ) from exc

    n = len(messages)
    dim = n + 2
    mat = IntegerMatrix(dim, dim)

    for i, msg in enumerate(messages):
        mat[i, i] = 1
        mat[i, n] = increment(msg)

    mat[n, n] = M

    mat[n + 1, n] = -target
    mat[n + 1, n + 1] = 1

    return mat


def vector_to_subset(vec, n, messages, target=TARGET):
    """
    Check whether a reduced lattice vector is an executable 0/1 subset.
    """
    vals = [int(vec[i]) for i in range(n)]
    middle = int(vec[n])
    last = int(vec[n + 1])

    # A lattice vector may be returned with the opposite sign.
    if last == -1:
        vals = [-x for x in vals]
        middle = -middle
        last = 1

    if last != 1:
        return None

    if middle != 0:
        return None

    if not all(x in (0, 1) for x in vals):
        return None

    indices = [i for i, x in enumerate(vals) if x == 1]

    if not indices:
        return None

    total = sum(increment(messages[i]) for i in indices) & (M - 1)

    if total != target:
        return None

    return indices


def solve_subset(messages, block_size=25, tours=3, verbose=True):
    """
    Reduce the subset-sum lattice with LLL + BKZ.

    The challenge has 670 actions.  We normally use 512 offline candidate
    messages, then execute the found subset four times online.

    If BKZ does not find a vector on the first pass, increase:
        --block
        --tours
        --candidates
    """
    try:
        from fpylll import BKZ, LLL
    except ImportError as exc:
        raise RuntimeError(
            "fpylll is required.\n"
            "Install it with:\n"
            "    pip install fpylll cysignals\n"
        ) from exc

    n = len(messages)

    print(f"[+] Candidate messages : {n}")
    print(f"[+] Lattice dimension   : {n + 2}")
    print(f"[+] BKZ block size      : {block_size}")
    print(f"[+] BKZ tours           : {tours}")

    mat = build_lattice(messages)

    print("[+] Running initial LLL ...")
    LLL.reduction(mat)

    # First scan after LLL.
    for row in range(mat.nrows):
        subset = vector_to_subset(mat[row], n, messages)
        if subset is not None:
            print(f"[+] Found subset after LLL: {len(subset)} messages")
            return subset

    for tour in range(1, tours + 1):
        print(f"[+] BKZ tour {tour}/{tours} ...")

        params = BKZ.Param(
            block_size=block_size,
            max_loops=1,
        )
        BKZ.reduction(mat, params)

        # Direct rows.
        for row in range(mat.nrows):
            subset = vector_to_subset(mat[row], n, messages)
            if subset is not None:
                print(
                    f"[+] Found subset after BKZ: "
                    f"{len(subset)} messages"
                )
                return subset

        # A useful fallback: scan short pairwise combinations of reduced rows.
        # This is deliberately bounded so it does not explode to O(n^2)
        # over the full 672-dimensional basis.
        limit = min(mat.nrows, 96)

        vectors = [
            [int(mat[i, j]) for j in range(mat.ncols)]
            for i in range(limit)
        ]

        for i in range(limit):
            for j in range(i + 1, limit):
                for sign in (1, -1):
                    candidate = [
                        vectors[i][k] + sign * vectors[j][k]
                        for k in range(mat.ncols)
                    ]

                    subset = vector_to_subset(
                        candidate, n, messages
                    )

                    if subset is not None:
                        print(
                            f"[+] Found subset from row combination: "
                            f"{len(subset)} messages"
                        )
                        return subset

    return None


# ---------------------------------------------------------------------------
# ECDSA recovery
# ---------------------------------------------------------------------------

def recover_k_and_x(sig1, sig2):
    """
    Recover nonce k and ECDSA private key x from two signatures
    made with the same nonce but different messages.

        s = k^-1 (z + x*r) mod N

        k = (z1-z2)/(s1-s2) mod N
        x = (s1*k-z1)/r mod N
    """
    r1, s1, z1 = sig1
    r2, s2, z2 = sig2

    if r1 != r2:
        raise ValueError(
            "Nonce reuse failed: r1 != r2\n"
            f"r1 = {hex(r1)}\n"
            f"r2 = {hex(r2)}"
        )

    denominator = (s1 - s2) % N

    if denominator == 0:
        raise ValueError(
            "s1 == s2. The two messages/signatures were not suitable."
        )

    k = ((z1 - z2) * inv(denominator, N)) % N
    x = ((s1 * k - z1) * inv(r1, N)) % N

    return k, x


# ---------------------------------------------------------------------------
# AES derivation
# ---------------------------------------------------------------------------

def derive_aes_material(k, qx, qy):
    """
    Server:

        S = k * Q
        key = S.x % 2^128
        iv  = S.x >> 128

    """
    shared = p256_mul(k, (qx, qy))

    if shared is None:
        raise ValueError("Shared point is infinity")

    sx = shared[0]

    key = (sx & ((1 << 128) - 1)).to_bytes(16, "big")
    iv = (sx >> 128).to_bytes(16, "big")

    return key, iv, shared


def decrypt_flag(cipher_hex, key, iv):
    ciphertext = bytes.fromhex(cipher_hex.strip())

    plaintext = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    ).decrypt(ciphertext)

    return unpad(plaintext, 16)


# ---------------------------------------------------------------------------
# Network client
# ---------------------------------------------------------------------------

class Client:
    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout

        self.sock = None
        self.buf = b""

    def connect(self):
        print(f"[+] Connecting to {self.host}:{self.port}")

        self.sock = socket.create_connection(
            (self.host, self.port),
            timeout=self.timeout,
        )

        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass

            self.sock = None

    def sendline(self, text):
        self.sock.sendall((text + "\n").encode())

    def recv_until(self, pattern=b"> "):
        if isinstance(pattern, str):
            pattern = pattern.encode()

        regex = re.compile(pattern)

        while True:
            match = regex.search(self.buf)

            if match:
                result = self.buf[:match.end()]
                self.buf = self.buf[match.end():]
                return result

            chunk = self.sock.recv(4096)

            if not chunk:
                raise ConnectionError(
                    "Server closed the connection."
                )

            self.buf += chunk

    def initial_banner(self):
        data = self.recv_until(b"> ")
        text = data.decode(errors="replace")

        # Primary parser.
        mx = re.search(
            r"Master Public Key Q\s*\(X\)\s*:\s*"
            r"(0x[0-9a-fA-F]+)",
            text,
        )

        my = re.search(
            r"Master Public Key Q\s*\(Y\)\s*:\s*"
            r"(0x[0-9a-fA-F]+)",
            text,
        )

        # More permissive fallback in case live banner wording differs.
        if not (mx and my):
            mx = re.search(
                r"Q\s*\(X\).*?"
                r"(0x[0-9a-fA-F]+)",
                text,
                re.S,
            )

            my = re.search(
                r"Q\s*\(Y\).*?"
                r"(0x[0-9a-fA-F]+)",
                text,
                re.S,
            )

        if not (mx and my):
            raise RuntimeError(
                "Could not parse public key Q from banner:\n"
                + text
            )

        qx = int(mx.group(1), 16)
        qy = int(my.group(1), 16)

        return qx, qy, text

    def sign(self, msg):
        self.sendline("1")

        self.recv_until(b"Message > ")
        self.sendline(msg)

        data = self.recv_until(b"> ")
        text = data.decode(errors="replace")

        mr = re.search(
            r"\br\s*:\s*(0x[0-9a-fA-F]+)",
            text,
        )

        ms = re.search(
            r"\bs\s*:\s*(0x[0-9a-fA-F]+)",
            text,
        )

        if not (mr and ms):
            raise RuntimeError(
                "Could not parse ECDSA signature:\n"
                + text
            )

        r = int(mr.group(1), 16)
        s = int(ms.group(1), 16)
        z = h_message(msg)

        return r, s, z

    def key_exchange(self):
        self.sendline("2")

        data = self.recv_until(b"> ")
        text = data.decode(errors="replace")

        m = re.search(
            r"\[+\]\s*Payload:\s*([0-9a-fA-F]+)",
            text,
        )

        if not m:
            m = re.search(
                r"Payload\s*:\s*([0-9a-fA-F]+)",
                text,
            )

        if not m:
            raise RuntimeError(
                "Could not parse encrypted payload:\n"
                + text
            )

        return m.group(1)


# ---------------------------------------------------------------------------
# Save/load offline plan
# ---------------------------------------------------------------------------

def save_plan(path, messages, indices):
    subset = [messages[i] for i in indices]

    total = sum(
        increment(messages[i])
        for i in indices
    ) & (M - 1)

    obj = {
        "messages": messages,
        "subset_indices": indices,
        "subset_messages": subset,
        "target": hex(TARGET),
        "sum_mod_2^256": hex(total),
        "subset_size": len(indices),
        "estimated_actions": 4 * len(indices) + 1,
    }

    Path(path).write_text(
        json.dumps(obj, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Saved plan: {path}")


def load_plan(path):
    obj = json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )

    messages = obj["messages"]
    indices = obj["subset_indices"]

    if not verify_subset(messages, indices):
        raise ValueError(
            "Saved subset is invalid: "
            "sum != 2^255 mod 2^256"
        )

    return messages, indices


# ---------------------------------------------------------------------------
# Offline phase
# ---------------------------------------------------------------------------

def offline(args):
    messages = make_messages(
        args.candidates,
        args.prefix,
    )

    print("[+] Target residue = 2^255")
    print("[+] Searching for executable 0/1 subset ...")

    indices = solve_subset(
        messages,
        block_size=args.block,
        tours=args.tours,
    )

    if indices is None:
        print()
        print("[-] No 0/1 subset was found.")
        print()
        print("Try:")
        print("    --candidates 600")
        print("    --block 30")
        print("    --tours 5")
        print()
        return 1

    if not verify_subset(messages, indices):
        raise RuntimeError(
            "Internal error: solver returned an invalid subset."
        )

    subset_size = len(indices)

    # We need:
    #
    #   cycle 1 = S + S
    #   cycle 2 = S(rotated) + S(rotated)
    #   key exchange
    #
    # total = 4*|S| + 1
    actions = 4 * subset_size + 1

    print(f"[+] Subset size        : {subset_size}")
    print(f"[+] Online actions     : {actions}/{MAX_ACTIONS}")

    if actions > MAX_ACTIONS:
        print(
            "[-] Subset is too large for the action budget."
        )
        print(
            "    Increase candidate count and rerun the lattice."
        )
        return 1

    save_plan(
        args.plan,
        messages,
        indices,
    )

    print()
    print("[+] Subset messages:")
    for n, i in enumerate(indices):
        print(f"    {n:03d}: {messages[i]}")

    print()
    print("[+] Offline phase complete.")
    print(
        f"[+] Run the online phase with:\n"
        f"    python solve.py online --plan {args.plan}"
    )

    return 0


# ---------------------------------------------------------------------------
# Online exploit
# ---------------------------------------------------------------------------

def online(args):
    messages, indices = load_plan(args.plan)
    subset = [messages[i] for i in indices]

    subset_size = len(subset)
    actions = 4 * subset_size + 1

    if actions > MAX_ACTIONS:
        raise RuntimeError(
            f"Plan needs {actions} actions, "
            f"server allows {MAX_ACTIONS}."
        )

    print(f"[+] Loaded subset with {subset_size} messages")
    print(f"[+] Required actions: {actions}/{MAX_ACTIONS}")

    client = Client(
        args.host,
        args.port,
        args.timeout,
    )

    try:
        client.connect()

        qx, qy, banner = client.initial_banner()

        print("[+] Public key Q:")
        print(f"    Q.x = {hex(qx)}")
        print(f"    Q.y = {hex(qy)}")

        # ---------------------------------------------------------------
        # Cycle 1
        # ---------------------------------------------------------------
        #
        # Sum(S) = 2^255 mod 2^256
        #
        # Sending S twice:
        #
        #   2 * Sum(S) = 2^256 = 0 mod 2^256
        #
        # Therefore the counter returns to its initial value.
        #
        print()
        print("[+] Cycle 1: S + S")

        sig1 = client.sign(subset[0])

        print(f"    sig1.r = {hex(sig1[0])}")
        print(f"    sig1.s = {hex(sig1[1])}")

        for msg in subset[1:]:
            client.sign(msg)

        for msg in subset:
            client.sign(msg)

        # ---------------------------------------------------------------
        # Cycle 2
        # ---------------------------------------------------------------
        #
        # Rotate the same subset so the first message is different.
        # The total sum is unchanged, so the counter returns again.
        #
        rotated = subset[1:] + subset[:1]

        print()
        print("[+] Cycle 2: rotated(S) + rotated(S)")

        sig2 = client.sign(rotated[0])

        print(f"    sig2.r = {hex(sig2[0])}")
        print(f"    sig2.s = {hex(sig2[1])}")

        for msg in rotated[1:]:
            client.sign(msg)

        for msg in rotated:
            client.sign(msg)

        # ---------------------------------------------------------------
        # ECDSA nonce recovery
        # ---------------------------------------------------------------

        print()
        print("[+] Recovering repeated nonce k ...")

        if sig1[0] != sig2[0]:
            raise RuntimeError(
                "The nonce was not reused: r1 != r2.\n"
                "This normally means the online message sequence "
                "did not return the hidden counter to its initial state."
            )

        k, x = recover_k_and_x(
            sig1,
            sig2,
        )

        print(f"[+] k = {hex(k)}")
        print(f"[+] x = {hex(x)}")

        # Verify private key against Q.
        recovered_q = p256_mul(x)

        if recovered_q != (qx, qy):
            raise RuntimeError(
                "Recovered private key does not reproduce Q."
            )

        print("[+] Private key verified: x*G == Q")

        # ---------------------------------------------------------------
        # Key exchange
        # ---------------------------------------------------------------
        #
        # Cycle 2 ended at the original counter.
        # Therefore exchange_key() uses the exact same k.
        #
        print()
        print("[+] Requesting key exchange ...")

        payload = client.key_exchange()

        print(f"[+] Ciphertext = {payload}")

        key, iv, shared = derive_aes_material(
            k,
            qx,
            qy,
        )

        print(f"[+] Shared point X = {hex(shared[0])}")
        print(f"[+] AES key        = {key.hex()}")
        print(f"[+] AES IV         = {iv.hex()}")

        plaintext = decrypt_flag(
            payload,
            key,
            iv,
        )

        print()
        print("=" * 60)
        print(f"FLAG = {plaintext.decode(errors='replace')}")
        print("=" * 60)

        return 0

    finally:
        client.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Microverse Battery solver"
    )

    parser.add_argument(
        "--host",
        default="31.97.37.38",
        help="Challenge host",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=1340,
        help="Challenge port",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="Socket timeout",
    )

    parser.add_argument(
        "--plan",
        default="microverse_plan.json",
        help="Offline plan file",
    )

    sub = parser.add_subparsers(
        dest="mode"
    )

    off = sub.add_parser(
        "offline",
        help="Find the modular subset using BKZ",
    )

    off.add_argument(
        "--candidates",
        type=int,
        default=512,
        help="Number of deterministic candidate messages",
    )

    off.add_argument(
        "--prefix",
        default="MB-",
        help="Candidate message prefix",
    )

    off.add_argument(
        "--block",
        type=int,
        default=25,
        help="BKZ block size",
    )

    off.add_argument(
        "--tours",
        type=int,
        default=3,
        help="Number of BKZ tours",
    )

    on = sub.add_parser(
        "online",
        help="Run the network exploit using a saved plan",
    )

    # No extra arguments are needed; global --host/--port/--plan work.

    args = parser.parse_args()

    # Convenient default:
    #
    #   no plan -> offline
    #   plan exists -> online
    #
    if args.mode is None:
        if Path(args.plan).exists():
            args.mode = "online"
        else:
            args.mode = "offline"
            args.candidates = 512
            args.prefix = "MB-"
            args.block = 25
            args.tours = 3

    if args.mode == "offline":
        return offline(args)

    if args.mode == "online":
        return online(args)

    parser.error("Unknown mode")


if __name__ == "__main__":
    raise SystemExit(main())
