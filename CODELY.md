# CODELY.md — NetGuard

## Ringkasan Proyek

**NetGuard** adalah aplikasi web *network device blocker*: memindai perangkat yang terhubung ke jaringan lokal (WiFi/LAN), lalu memblokir perangkat tertentu menggunakan **ARP spoofing** melalui GUI web berbasis **Flask**. Semua logika ada di satu file Python per varian, dengan UI web single-file (dark theme, mobile-friendly, `lang="id"`).

Proyek ini memiliki **dua varian aplikasi**:

| Lokasi | Platform | Scan | Blokir | Keterangan |
|---|---|---|---|---|
| `app.py` (root) | Linux (Kali NetHunter) | `nmap -sn` | `arpspoof` (dsniff) via subprocess | Versi asli, Linux-only |
| `windows/app.py` | Cross-platform (Windows + Linux) | `scapy` (Windows) / `nmap` (Linux) | thread scapy (Windows) / `arpspoof` (Linux) | Versi lebih baru dan lebih lengkap, deteksi via `sys.platform` |

## Struktur Direktori

```
netguard/
├── app.py                    # Varian Linux: nmap + arpspoof (Flask server)
├── templates/
│   └── index.html            # GUI web (identik dengan windows/templates/index.html)
├── windows/
│   ├── app.py                # Varian cross-platform: scapy (Windows) / nmap+arpspoof (Linux)
│   ├── templates/
│   │   └── index.html        # Salinan identik dari templates/index.html (md5 sama)
│   ├── run.bat               # Launcher double-click → memanggil run.ps1
│   ├── run.ps1               # Launcher PowerShell: cek admin, Python, pip, Npcap (auto-setup)
│   ├── requirements.txt      # flask>=3.0, scapy>=2.5
│   └── README.md             # Panduan instalasi & troubleshooting Windows
└── logs/                     # Debug log Codely CLI — BUKAN bagian aplikasi (abaikan)
```

## Menjalankan Aplikasi

Server Flask bind ke `0.0.0.0:5000`; akses via `http://127.0.0.1:5000` (UI terbuka otomatis di Windows via launcher).

### Linux (varian root — `app.py`)

```bash
# Butuh root untuk arpspoof dan menulis /proc/sys/net/ipv4/ip_forward
sudo python3 app.py
```

Dependensi eksternal yang harus terpasang: `python3-flask` (atau `pip install flask`), `nmap`, `arpspoof` (paket `dsniff`). Tidak ada `requirements.txt` di root — TODO jika varian ini dikembangkan lagi.

### Windows (varian `windows/app.py`)

Cara cepat: jalankan `run.bat` (atau `run.ps1` **sebagai Administrator**). Launcher otomatis: cek hak admin (menawarkan elevasi ulang), cek Python, `pip install -r requirements.txt`, cek/download Npcap, lalu menjalankan `python app.py` dan membuka browser.

Cara manual:

```powershell
pip install -r requirements.txt
python app.py   # harus sebagai Administrator
```

Syarat Windows: Python 3.10+, Npcap (mode WinPcap-compatible) untuk injeksi paket ARP.

## Dependensi

| Komponen | Dipakai oleh | Catatan |
|---|---|---|
| Flask ≥ 3.0 | Kedua varian | Web server + REST API |
| Scapy ≥ 2.5 | `windows/app.py` (Windows) | Scan ARP (`srp`) + spoofing via thread |
| Npcap | Windows | Akses raw packet; wajib untuk blokir di Windows |
| nmap | Kedua varian (Linux) | Scan host (`nmap -sn -n <subnet>`) |
| arpspoof (dsniff) | Kedua varian (Linux) | ARP spoofing, 2 proses per target |

## Arsitektur & API

State blocking disimpan in-memory di dict global `blocked`:
- Linux: `{ip: {"mac": ..., "pids": [pid1, pid2]}}` — dua proses `arpspoof` (target→gateway dan gateway→target), dihentikan dengan `SIGTERM`.
- Windows: `{ip: {"thread": Thread, "stop": Event}}` — thread daemon mengirim paket ARP tiap 1 detik; dihentikan via `stop_event.set()`.

Deteksi jaringan dilakukan runtime: interface/subnet/gateway/IP sendiri via `ip route` / `ip addr` (Linux), atau `route print` / `netsh` / socket UDP (Windows). Vendor perangkat dari output nmap atau tabel OUI hardcode di `windows/app.py`.

Endpoint API (identik di kedua varian, semua JSON):

| Endpoint | Metode | Fungsi |
|---|---|---|
| `/` | GET | Halaman UI (`index.html`) |
| `/api/scan` | GET | Scan jaringan → `devices`, `gateway`, `interface`, `subnet`, `own_ip` |
| `/api/block` | POST `{ip, mac}` | Blokir satu perangkat via ARP spoofing |
| `/api/unblock` | POST `{ip}` | Hentikan spoofing untuk satu perangkat |
| `/api/block_all` | POST | Blokir semua kecuali diri sendiri & gateway |
| `/api/unblock_all` | POST | Lepaskan semua blokir |
| `/api/status` | GET | Daftar IP terblokir + pembersihan entri proses/thread mati |

UI (`templates/index.html`) adalah satu file dengan CSS dan JavaScript inline (tanpa framework): kartu perangkat, tombol Block/Unblock per kartu, Block All/Unblock All, toast notifikasi, spinner saat scan, dan auto-refresh status.

## Konvensi Pengembangan

- **Python**: satu file aplikasi, fungsi `snake_case` dengan docstring satu baris; section dipisah komentar banner `# ==== ... ====`; pemilihan platform via flag modul (`IS_WINDOWS`/`IS_LINUX`) atau deteksi langsung; alat eksternal dipanggil dengan `subprocess` dan output di-parse dengan regex; error API dikembalikan sebagai `jsonify({"error": ...})` dengan kode HTTP 400/500.
- **HTML/UI**: single-file, CSS/JS inline, tanpa build step; ikon SVG inline; tema gelap; notifikasi via toast; kompatibel mobile.
- **Duplikasi penting**: `templates/index.html` dan `windows/templates/index.html` **harus identik** (md5 sama saat analisis). Setiap perubahan UI harus diterapkan di KEDUA file.
- **Divergensi `app.py`**: kedua `app.py` berbeda (root 365 baris, windows 625 baris). Jangan asumsikan keduanya sinkron — `windows/app.py` adalah versi cross-platform yang lebih lengkap (termasuk vendor OUI DB dan cleanup thread).

## Build, Test, dan Lint

- Tidak ada build step, test suite, linter, atau formatter yang dikonfigurasi.
- Verifikasi manual: jalankan aplikasi dan buka `http://127.0.0.1:5000`, lalu cek endpoint (mis. `curl http://127.0.0.1:5000/api/status`).
- TODO: tambahkan `requirements.txt` di root jika varian Linux dikembangkan.

## Catatan Penting

- **Hak akses**: di Linux jalankan sebagai root (`sudo`); di Windows sebagai Administrator — diperlukan untuk ARP spoofing dan `ip_forward`.
- **Blokir tidak persisten**: blokir hanya aktif selama server berjalan; menutup proses/server menghentikan semua spoofing.
- **Etika**: ini alat manipulasi jaringan (ARP spoofing). Hanya untuk jaringan milik sendiri / penggunaan edukatif yang sah.
- `logs/` berisi trace debug Codely CLI (`CODELY_STARTUP_TRACE`), bukan log aplikasi NetGuard — jangan dianggap bagian kode.
- Direktori ini tidak dikelola git.
