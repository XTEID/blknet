# blknet

**blknet** adalah aplikasi web *network device blocker*: memindai perangkat yang terhubung ke jaringan lokal (WiFi/LAN), lalu memblokir perangkat tertentu menggunakan **ARP spoofing** — semuanya melalui GUI web berbasis **Flask**.

> ⚠️ **Etika penggunaan:** ini adalah alat manipulasi jaringan (ARP spoofing). Gunakan **hanya pada jaringan milik sendiri** atau untuk penggunaan edukatif yang sah. Menggunakan alat ini pada jaringan tanpa izin adalah tindakan ilegal.

## Fitur

- 🔍 **Scan jaringan otomatis** — mendeteksi semua perangkat di subnet lokal beserta vendor perangkatnya
- 🚫 **Blokir per perangkat** — putuskan koneksi internet perangkat tertentu via ARP spoofing
- 🔓 **Buka blokir** — hentikan spoofing kapan saja, per perangkat atau semuanya sekaligus
- ⚡ **Block All / Unblock All** — blokir semua perangkat sekaligus (kecuali diri sendiri & gateway)
- 🌐 **GUI web** — tema gelap, mobile-friendly, notifikasi toast, auto-refresh status
- 🖥️ **Dua varian** — Linux (Kali NetHunter) dan cross-platform (Windows + Linux)

## Cara Kerja

Blokir bekerja di **Layer 2 (ARP)**, bukan Layer 4 — jadi blokirnya bersifat **per-perangkat (per-IP)**: seluruh koneksivitas IP perangkat target (semua port, semua protokol) terpengaruh sekaligus.

- **Linux**: `nmap -sn` untuk scan, `arpspoof` (dsniff) via subprocess — dua proses per target (target→gateway dan gateway→target).
- **Windows**: `scapy` untuk scan ARP (`srp`) + spoofing via thread daemon yang mengirim paket ARP tiap 1 detik. Butuh **Npcap** (mode WinPcap-compatible).

Blokir **tidak persisten**: hanya aktif selama server berjalan.

## Struktur Project

```
blknet/
├── app.py                    # Varian Linux: nmap + arpspoof
├── templates/index.html      # GUI web
├── windows/
│   ├── app.py                # Varian cross-platform: scapy / nmap+arpspoof
│   ├── templates/index.html  # Salinan GUI (identik)
│   ├── run.bat / run.ps1     # Launcher Windows (auto-setup + cek admin)
│   ├── requirements.txt
│   └── README.md
└── .gitignore
```

## Menjalankan (Linux)

```bash
sudo python3 app.py
```

Butuh **root** untuk `arpspoof` dan menulis `/proc/sys/net/ipv4/ip_forward`. Akses UI di `http://127.0.0.1:5000`.

Dependensi eksternal: `python3-flask` (atau `pip install flask`), `nmap`, `arpspoof` (paket `dsniff`).

## Menjalankan (Windows)

Cara cepat — jalankan `run.bat` (atau `run.ps1` **sebagai Administrator**). Launcher otomatis: cek hak admin, cek Python, `pip install -r requirements.txt`, cek/download Npcap, lalu menjalankan server dan membuka browser.

Cara manual:

```powershell
pip install -r requirements.txt
python app.py   # harus sebagai Administrator
```

Syarat: Python 3.10+, Npcap, hak Administrator.

## API

| Endpoint | Metode | Fungsi |
|---|---|---|
| `/api/scan` | GET | Scan jaringan → daftar perangkat, gateway, subnet |
| `/api/block` | POST `{ip, mac}` | Blokir satu perangkat |
| `/api/unblock` | POST `{ip}` | Lepaskan blokir satu perangkat |
| `/api/block_all` | POST | Blokir semua kecuali diri sendiri & gateway |
| `/api/unblock_all` | POST | Lepaskan semua blokir |
| `/api/status` | GET | Daftar IP yang sedang terblokir |

Semua endpoint mengembalikan JSON.

## Lisensi

Project ini dilisensikan di bawah **[GPL-2.0-or-later](LICENSE)** (SPDX: `GPL-2.0-or-later`).

Lisensi GPL dipilih karena varian Windows mengimpor [Scapy](https://scapy.net/) yang berlisensi **GPL v2** — dengan lisensi yang kompatibel dengan GPL, distribusi project ini tetap sah.
