# KAITO'S CTF 2026 — Writeup

Writeup CTF **Kaito** oleh Ravi, Raihan Taufik,disusun per kategori.

## Daftar Challenge

| # | Challenge | Kategori | Kesulitan | Flag |
|---|-----------|----------|:---------:|------|
| 1 | Welcome Flag | [Beginner](Beginner/01-welcome-flag.md) | ★☆☆☆☆ | `WARMUP{175_n07_m491c_175_d3d1c4710n}` |
| 2 | Kid1412 | [Beginner](Beginner/02-kid1412.md) | ★★☆☆☆ | `KAITO{kid_1412_always_leaves_a_calling_card}` |
| 3 | Heist Notice | [Stego](Stego/03-heist-notice.md) | ★★☆☆☆ | `KAITO{tonights_target_is_the_moonlight_sonata}` |
| 4 | TarSnap Archive | [Web](Web/04-tarsnap-archive.md) | ★★★★☆ | `Kaito{t4r_syml1nk_4rb1tr4ry_f1l3_r34d_3xpl01t_91a4}` |
| 5 | Showtime | [Reverse](Reverse/05-showtime.md) | ★★★☆☆ | `KAITO{its_showtime_ladies_and_gentlemen}` |
| 6 | Freewill | [Misc](Misc/06-freewill.md) | ★★★☆☆ | `KAITO{you_chose_nothing_i_chose_everything}` |
| 7 | Smoke Screen | [Forensic](Forensic/07-smoke-screen.md) | ★★★☆☆ | `KAITO{cocoon_of_smoke_gilded_escape}` |
| 8 | Pizza Syndicate | [Forensic](Forensic/08-pizza-syndicate.md) | ★★★★★ | `Kaito{n4p0l1_s4uc3_m4f14_m3m0ry_c4rv1ng_p1zz4_1924}` |
| 9 | He's Not Findable | [Crypto](Crypto/09-hes-not-findable.md) | ★★★★☆ | `Kaito{c3ntr4l_f1n1t3_curv3_hnp_l4tt1c3_c137}` |
| 10 | The Omega Trigger | [Crypto](Crypto/10-the-omega-trigger.md) | ★★★★☆ | `Kaito{0m3g4_d3v1c3_matsumoto_imai_patarin_differential}` |
| 11 | The Berglas Effect | [Reverse](Reverse/11-berglas.md) | ★★★★☆ | `KAITO{any_card_any_number_no_method_known}` |
| 12 | What a Good Spot | [OSINT](OSINT/12-what-a-good-spot.md) | ★★★☆☆ | `Kaito{55.994,-3.385}` |
| 13 | Neko Haven VIP | [Beginner](Beginner/13-neko-haven-vip.md) | ★★☆☆☆ | `Kaito{n3k0_c4fe_sip_purr_fl4g_991}` |
| 14 | Disguises | [Beginner](Beginner/14-disguises.md) | ★★★★★ | `KAITO{the_disguise_fools_eyes_not_the_timeline}` |
| 15 | Crypt15 | [Crypto](Crypto/15-crypt15.md) | ★★★☆☆ | `KAITO{signal_protocol_crypt15_backup_decrypted}` |
| 16 | Teleprinter TP-52 | [Crypto](Crypto/16-teleprinter.md) | ★★★★☆ | `Kaito{QAJRCEBTHUZNLKOVYMIWXPDFGS_PBTUXACNHVSKWEMRDGJOQLIFYZ_IOWKZNVDALUFPQYSJTBCMEGRXH_AQ_BH_CX_DZ_ES_FR_GV_IP_JT_KL_MO_NU_WY}` |
| 17 | Pandora | [Crypto](Crypto/17-pandora.md) | ★★★★★ | `KAITO{pandora_holds_the_kuroba_legacy}` |
| 18 | Freewill-Hard | [Misc](Misc/18-freewill-hard.md) | ★★★☆☆ | `KAITO{authorship_was_never_yours}` |
| 19 | That Creepy Episode | [OSINT](OSINT/19-that-creepy-episode.md) | ★★★☆☆ | `Kaito{Dogged_6}` |
| 20 | The Jackal's Alias | [Web](Web/20-the-jackals-alias.md) | ★★★★☆ | `Kaito{bl1nd_j50nqu3ry_byp455_v14_b00l34n_4r1thm3t1c}` |
| 21 | Fear No Mort | [Web](Web/21-fear-no-mort.md) | ★★★★☆ | `Kaito{th3_d00r_w45_n3v3r_1n_th3_r00m_58e4c12a}` |

## Statistik

- **Solved:** 21 challenge
- **Kategori:** Beginner, Stego, Web, Reverse, Misc, Forensic, Crypto, OSINT

## Struktur Folder

```
Kaito-CTF/
├── README.md
├── assets/                 # semua screenshot
│   └── README.md           # konvensi penamaan gambar
├── Beginner/
├── Stego/
├── Web/
├── Reverse/
├── Misc/
├── Forensic/
├── Crypto/
└── OSINT/
```

## Konvensi Gambar

Semua gambar disimpan di folder `assets/`, penamaan mengikuti `assets/README.md`.
