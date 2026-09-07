# Konvensi Gambar Writeup

Simpan semua screenshot di folder `assets/` ini (satu folder untuk semua kategori). Nama file pakai nomor urut challenge agar gampang dirujuk dari tiap writeup.

## Aturan penamaan

```
assets/
  01-welcome-flag-<deskripsi>.png
  02-kid1412-<deskripsi>.png
  03-heist-notice-<deskripsi>.png
  04-tarsnap-<deskripsi>.png
  05-showtime-<deskripsi>.png
  06-freewill-<deskripsi>.png
  07-smoke-screen-<deskripsi>.png
  08-pizza-syndicate-<deskripsi>.png
```

Contoh deskripsi: `homepage`, `inspect-element`, `flag`, `decode-output`, `hexdump`, `file-size`, `payload`.

## Cara pakai di markdown

Karena gambar di `assets/` dan writeup di dalam folder kategori, path-nya pakai `../assets/`:

```markdown
![Deskripsi gambar](../assets/01-welcome-flag-homepage.png)
```

Screenshot yang sudah kamu ambil tinggal di-copy/drag ke folder `assets/`, lalu ganti placeholder `<!-- SCREENSHOT ... -->` di tiap writeup dengan baris `![](...)` yang sesuai.
