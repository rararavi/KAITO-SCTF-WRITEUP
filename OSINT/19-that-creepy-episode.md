# Kaito CTF - Creepy TV Scene (OSINT)

- Write-Up Author: reybong
- Category: OSINT
- Flag: `Kaito{Dogged_6}`

## Challenge Description

> I remember catching this weirdly unsettling scene on TV as a kid and it stuck with me.........for years. Can you track down the episode title and the minute mark where this clip appears?

**Target Assets:**
- `assets/19-that-creepy-episode-1.png`
- `assets/19-that-creepy-episode-2.png`
- `assets/19-that-creepy-episode-3.png`

## Analisis & Langkah Penyelesaian

1. **Reverse Image Search (Google Lens):**
   - Melakukan reverse image search terhadap tangkapan layar adegan hijau misterius (`19-that-creepy-episode-1.png`).
   - Google Lens mengidentifikasi video klip tersebut berasal dari serial **Power Rangers S.P.D.** episode 5.

2. **Identifikasi Nama Episode:**
   - Melakukan pencarian Google untuk `POWER RANGERS SPD Episode-5` (`19-that-creepy-episode-2.png`).
   - Ditemukan judul episode resmi: **`Dogged`** (S13 | E05).

3. **Menentukan Menit Penampakan (Minute Mark):**
   - Membuka video full episode *Dogged | SPD | Full Episode | S13 | E05* di YouTube channel *Power Rangers Official* (`19-that-creepy-episode-3.png`).
   - Pada timestamp **7:34** (menit ke-7), adegan karakter yang berubah menjadi bayangan hijau di bangku taman muncul secara identik.

## Penyusunan Flag

Format flag: `Kaito{EpisodeName_M}`

- **EpisodeName:** `Dogged`
- **Minute (M):** `6`

**Contoh Format Flag:** `Kaito{Dogged_6}`
