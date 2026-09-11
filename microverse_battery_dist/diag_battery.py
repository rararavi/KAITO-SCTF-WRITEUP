import socket, time, sys

HOST = "31.97.37.38"
PORT = 1340

s = socket.create_connection((HOST, PORT), timeout=15)
s.settimeout(3)

buf = b""
start = time.time()
print("Reading for up to 30 seconds...")
while time.time() - start < 30:
    try:
        chunk = s.recv(65536)
        if not chunk:
            print("\n--- connection closed ---")
            break
        buf += chunk
        sys.stdout.write(chunk.decode(errors="replace"))
        sys.stdout.flush()
    except socket.timeout:
        continue

with open("battery_banner.txt", "wb") as f:
    f.write(buf)
print("\n\n=== saved to battery_banner.txt ===")