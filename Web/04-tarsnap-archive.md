# Kaito CTF - TarSnap Archive

- Write-Up Author: Ravi
- Category: Web
- Flag: *(belum)*

## Challenge Description

> TarSnap is the next-generation cloud portfolio ingestion engine designed for digital artists and creative developers. Upload your `.tar.gz` portfolio archives, unpack high-resolution assets, and preview them live in your private cloud sandbox. Our devs built this airtight, there's no way any company data is getting leaked.

**Target URL:** `https://tarsnap-vsuv8iaz.instance.tbf1.online/`

## Analisis

Aplikasi web menerima upload arsip `.tar.gz`, kemudian mengekstrak dan menampilkan aset di dalam sandbox. Deskripsi "no way any company data is getting leaked" menjadi petunjuk bahwa celahnya kemungkinan besar adalah **path traversal** saat proses ekstraksi arsip.

<!-- SCREENSHOT: tampilan web TarSnap -->
![Tampilan web TarSnap](../assets/04-tarsnap-web.png)

## Langkah Menemukan Flag

<!-- TODO: lengkapi langkah eksploitasi (path traversal / archive upload) -->

1. *(Langkah eksploitasi belum diisi)*
2. *(dst.)*

<!-- SCREENSHOT: payload yang dikirim -->
![Payload eksploitasi](../assets/04-tarsnap-payload.png)

<!-- SCREENSHOT: hasil flag -->
![Hasil flag](../assets/04-tarsnap-flag.png)

## Kesimpulan

<!-- TODO -->

**Flag:** `<!-- TODO -->`
