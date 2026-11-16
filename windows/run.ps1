# blknet — PowerShell Launcher (Windows)
# Run as Administrator!
# Usage: Right-click -> Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File run.ps1

param(
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  blknet - Network Device Blocker" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  [!] Not running as Administrator!" -ForegroundColor Red
    Write-Host "  blknet needs Admin to send ARP packets." -ForegroundColor Yellow
    Write-Host "  Right-click -> Run as Administrator" -ForegroundColor Yellow
    Write-Host ""
    $retry = Read-Host "  Restart as Admin? (Y/n)"
    if ($retry -ne "n") {
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}

# Check Python
Write-Host ""
Write-Host "  [*] Checking Python..." -ForegroundColor Yellow
try {
    $pyVer = python --version 2>&1
    Write-Host "  [OK] $pyVer" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python not found!" -ForegroundColor Red
    Write-Host "  Install from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  Make sure to check 'Add Python to PATH'" -ForegroundColor Yellow
    Read-Host "  Press Enter to exit"
    exit 1
}

# Check/install dependencies
Write-Host "  [*] Checking dependencies..." -ForegroundColor Yellow
$needInstall = $false
try {
    python -c "import flask" 2>$null
    if ($LASTEXITCODE -ne 0) { $needInstall = $true }
} catch { $needInstall = $true }

try {
    python -c "import scapy" 2>$null
    if ($LASTEXITCODE -ne 0) { $needInstall = $true }
} catch { $needInstall = $true }

if ($needInstall) {
    Write-Host "  [*] Installing dependencies..." -ForegroundColor Yellow
    pip install -r "$ScriptDir\requirements.txt" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to install dependencies" -ForegroundColor Red
        Read-Host "  Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "  [OK] All dependencies present" -ForegroundColor Green
}

# Check Npcap
Write-Host "  [*] Checking Npcap..." -ForegroundColor Yellow
$npcapInstalled = $false
$npcapPath = "C:\Windows\System32\Npcap"
if (Test-Path $npcapPath) {
    $npcapInstalled = $true
}
# Also check registry
if (-not $npcapInstalled) {
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
    if ($reg) { $npcapInstalled = $true }
}
if (-not $npcapInstalled) {
    $reg2 = Get-ItemProperty "HKLM:\SOFTWARE\Npcap" -ErrorAction SilentlyContinue
    if ($reg2) { $npcapInstalled = $true }
}

if ($npcapInstalled) {
    Write-Host "  [OK] Npcap detected" -ForegroundColor Green
} else {
    Write-Host "  [!] Npcap not found!" -ForegroundColor Red
    Write-Host "  Npcap is required for ARP packet injection." -ForegroundColor Yellow
    Write-Host ""
    $installNpcap = Read-Host "  Download and install Npcap now? (Y/n)"
    if ($installNpcap -ne "n") {
        Write-Host "  [*] Downloading Npcap installer..." -ForegroundColor Yellow
        $npcapUrl = "https://npcap.com/dist/npcap-1.79.exe"
        $npcapExe = "$env:TEMP\npcap-installer.exe"
        try {
            Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapExe -UseBasicParsing
            Write-Host "  [*] Launching installer (select 'Install Npcap in WinPcap API-compatible Mode')..." -ForegroundColor Yellow
            Start-Process -FilePath $npcapExe -Wait
            Write-Host "  [OK] Npcap installed" -ForegroundColor Green
        } catch {
            Write-Host "  [ERROR] Download failed." -ForegroundColor Red
            Write-Host "  Download manually from: https://npcap.com/#download" -ForegroundColor Yellow
            Read-Host "  Press Enter to exit"
            exit 1
        }
    } else {
        Write-Host "  [!] ARP spoofing will not work without Npcap." -ForegroundColor Red
        Write-Host "      Scanning will still work but blocking won't." -ForegroundColor Yellow
    }
}

# Start server
Write-Host ""
Write-Host "  [*] Starting blknet..." -ForegroundColor Yellow
Write-Host "  [*] Open browser: http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "  [*] Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""

# Auto-open browser after 2 seconds
Start-Job -ScriptBlock {
    param($p)
    Start-Sleep 2
    Start-Process "http://127.0.0.1:$p"
} -ArgumentList $Port | Out-Null

python "$ScriptDir\app.py"
