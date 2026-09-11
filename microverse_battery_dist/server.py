import os
import sys
import secrets
import hashlib
import threading
import socketserver
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, long_to_bytes

FLAG = os.environ.get("FLAG", "KAITO{test_flag_for_local_debugging}")
PORT = int(os.environ.get("PORT", 1340))
MAX_ACTIONS = 670

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_zero(self):
        return self.x is None and self.y is None

    def __add__(self, other):
        if self.is_zero(): return other
        if other.is_zero(): return self
        if self.x == other.x:
            if (self.y + other.y) % P == 0:
                return Point(None, None)
            slope = (3 * self.x * self.x + A) * pow(2 * self.y, -1, P) % P
        else:
            slope = (other.y - self.y) * pow(other.x - self.x, -1, P) % P
        x3 = (slope * slope - self.x - other.x) % P
        y3 = (slope * (self.x - x3) - self.y) % P
        return Point(x3, y3)

    def __rmul__(self, scalar):
        scalar = scalar % N
        if scalar == 0: return Point(None, None)
        res = Point(None, None)
        curr = self
        while scalar > 0:
            if scalar & 1:
                res = res + curr
            curr = curr + curr
            scalar >>= 1
        return res

G = Point(Gx, Gy)

def h(m: str) -> int:
    return bytes_to_long(hashlib.sha256(m.encode()).digest())

class QuantumTachyonStepper:
    def __init__(self):
        self.cnt = bytes_to_long(secrets.token_bytes(32))
        self.mod = 2**256

    def next(self, m=None):
        res = bytes_to_long(hashlib.sha256(str(self.cnt).encode()).digest())
        a = 0 if m is None else h(m)
        self.cnt = (self.cnt + 1 + a) % self.mod
        return res

class ChallengeSession:
    def __init__(self, rfile, wfile):
        self.rfile = rfile
        self.wfile = wfile
        self.stepper = QuantumTachyonStepper()
        self.x = bytes_to_long(secrets.token_bytes(32)) % N
        while self.x == 0:
            self.x = bytes_to_long(secrets.token_bytes(32)) % N
        self.Q = self.x * G
        self.actions_used = 0

    def send(self, msg=""):
        self.wfile.write((msg + "
").encode("utf-8"))
        self.wfile.flush()

    def readline(self, prompt=""):
        if prompt:
            self.wfile.write(prompt.encode("utf-8"))
            self.wfile.flush()
        line = self.rfile.readline()
        if not line:
            raise ConnectionResetError()
        return line.decode("utf-8").strip()

    def sign_tachyon(self, m: str):
        z = h(m)
        k = self.stepper.next(m)
        R = k * G
        r = R.x % N
        s = (pow(k, -1, N) * z + self.x * r) % N
        return r, s

    def exchange_key(self):
        k = self.stepper.next(None)
        S = k * self.Q
        key_bytes = long_to_bytes(S.x % (2**128), 16)
        iv_bytes = long_to_bytes(S.x >> 128, 16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        ciphertext = cipher.encrypt(pad(FLAG.encode(), 16))
        return ciphertext.hex()

    def handle(self):
        try:
            self.send(f"[+] Master Public Key Q (X): {hex(self.Q.x)}")
            self.send(f"[+] Master Public Key Q (Y): {hex(self.Q.y)}")

            while True:
                self.send("
[ Options ]")
                self.send(f"[1] Sign Message ({self.actions_used}/{MAX_ACTIONS} used)")
                self.send("[2] Key Exchange")
                self.send("[3] Disconnect")

                choice = self.readline("> ")
                if choice == "1":
                    if self.actions_used >= MAX_ACTIONS:
                        self.send("[-] Action limit reached.")
                        continue
                    
                    m_input = self.readline("Message > ")
                    self.actions_used += 1
                    r, s = self.sign_tachyon(m_input)
                    self.send(f"[+] Signature:")
                    self.send(f"    r: {hex(r)}")
                    self.send(f"    s: {hex(s)}")

                elif choice == "2":
                    if self.actions_used >= MAX_ACTIONS:
                        self.send("[-] Action limit reached.")
                        continue
                    
                    self.actions_used += 1
                    enc_hex = self.exchange_key()
                    self.send(f"[+] Payload: {enc_hex}")

                elif choice == "3":
                    return
                else:
                    self.send("[-] Invalid option.")

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            try:
                self.send(f"[-] Error: {e}")
            except Exception:
                pass

class ThreadedTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        session = ChallengeSession(self.rfile, self.wfile)
        session.handle()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    server = ThreadedTCPServer(("0.0.0.0", PORT), ThreadedTCPHandler)
    server.serve_forever()
