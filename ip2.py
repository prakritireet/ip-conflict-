from scapy.all import ARP, Ether, srp
from collections import defaultdict
import time

def scan_network(network):
    """Scan the given network and return IP-MAC mappings."""
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def detect_conflicts(devices):
    """Check for IP or MAC address conflicts."""
    ip_to_mac = defaultdict(list)
    mac_to_ip = defaultdict(list)

    for d in devices:
        ip_to_mac[d['ip']].append(d['mac'])
        mac_to_ip[d['mac']].append(d['ip'])

    conflicts = []

    # Multiple MACs for same IP
    for ip, macs in ip_to_mac.items():
        if len(set(macs)) > 1:
            conflicts.append(f"⚠️ IP Conflict: {ip} mapped to multiple MACs: {macs}")

    # Multiple IPs for same MAC (optional warning)
    for mac, ips in mac_to_ip.items():
        if len(set(ips)) > 1:
            conflicts.append(f"ℹ️ Device {mac} responding to multiple IPs: {ips}")

    return conflicts

def main():
    print("🔍 IP Address Conflict Detector 🔍")
    print("----------------------------------")
    network = input("Enter IP address or subnet (e.g., 192.168.1.0/24): ").strip()

    print(f"\nScanning network: {network}")
    devices = scan_network(network)
    print(f"\nDevices found: {len(devices)}")

    for d in devices:
        print(f"IP: {d['ip']}  |  MAC: {d['mac']}")

    conflicts = detect_conflicts(devices)

    print("\n----------------------------------")
    if conflicts:
        print("🚨 Conflicts detected:")
        for c in conflicts:
            print(c)
    else:
        print("✅ No IP conflicts detected.")
    print("----------------------------------")

if __name__ == "__main__":
    main()















