# NetGuard — Windows Installation Guide

## Quick Start

1. **Install Python 3.10+**
   - Download: https://www.python.org/downloads/
   - Check "Add Python to PATH" during install

2. **Double-click `run.bat`**
   - Or right-click `run.ps1` -> Run with PowerShell
   - Must run as Administrator

3. The script will auto-install:
   - Python packages (flask, scapy)
   - Npcap (for ARP packet injection)

4. Browser opens automatically at `http://127.0.0.1:5000`

## Manual Setup

```powershell
pip install -r requirements.txt
python app.py
```

## Requirements

| Requirement | Purpose | Auto-installed? |
|-------------|---------|-----------------|
| Python 3.10+ | Runtime | No (manual) |
| Flask | Web server | Yes (via pip) |
| Scapy | ARP scanning + spoofing | Yes (via pip) |
| Npcap | Raw packet access on Windows | Yes (via script) |

## How It Works (Windows)

- **Scanning**: Uses `scapy` ARP scan (no nmap needed)
- **Blocking**: Uses `scapy` ARP spoofing (no arpspoof needed)
- **Web UI**: Same dark theme, mobile + desktop friendly

## File Structure

```
netguard/windows/
├── app.py              # Main application (cross-platform)
├── run.ps1             # PowerShell launcher (auto-setup)
├── run.bat             # Batch launcher (double-click)
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── templates/
    └── index.html       # Web GUI
```

## Troubleshooting

### "Access denied" or ARP spoof not working
- Run as Administrator (right-click -> Run as Administrator)

### "No module named 'scapy'"
```
pip install scapy
```

### "No module named 'flask'"
```
pip install flask
```

### Npcap not detected
- Reinstall Npcap: https://npcap.com/#download
- Check "Install Npcap in WinPcap API-compatible Mode"

### Port 5000 already in use
```
# Find and kill process on port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

## Notes

- Windows Defender may flag scapy ARP packets — allow if prompted
- NetGuard must keep running to maintain blocks
- Closing the PowerShell window stops all blocking
