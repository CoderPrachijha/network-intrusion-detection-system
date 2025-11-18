from scapy.all import sniff, IP, TCP, UDP, get_if_list
from collections import defaultdict
import time
import re

print("\n--- Network IDS Started ---")
print("Detecting active network interface...\n")

# -----------------------------------------------------
# FIND ACTIVE NETWORK INTERFACE
# -----------------------------------------------------
interfaces = get_if_list()
print("Available interfaces:", interfaces)

# Choose correct interface
# Try Wi-Fi first, then Ethernet, then fall back to first interface
iface = None
for i in interfaces:
    if "Wi-Fi" in i or "WiFi" in i:
        iface = i
        break
for i in interfaces:
    if "Ethernet" in i and iface is None:
        iface = i

if iface is None:
    iface = interfaces[0]  # fallback

print(f"\nUsing interface: {iface}\n")

print("--- Network IDS Started ---")
print("Capturing packets in real-time...\n")

# -----------------------------------------------------
# TRACKERS
# -----------------------------------------------------
port_scan_tracker = defaultdict(set)
dos_tracker = defaultdict(list)
PACKET_LIMIT = 60

SUSPICIOUS_KEYWORDS = [
    "select", "union", "drop", "insert", "alert(", "<script>", "or 1=1",
    "'--", "sleep(", "benchmark(", "admin", "password"
]

# -----------------------------------------------------
# SUSPICIOUS PAYLOAD DETECTION
# -----------------------------------------------------
def detect_suspicious_http(raw_data):
    try:
        decoded = raw_data.decode("utf-8", errors="ignore").lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in decoded:
                print(f"[ALERT] Suspicious HTTP payload detected → Keyword: {kw}")
                print("Payload:", decoded[:100], "...\n")
                return
    except:
        pass


# -----------------------------------------------------
# PACKET PROCESSING
# -----------------------------------------------------
def process_packet(packet):
    print("[PACKET] detected")

    # -------------- BASIC PACKET INFO ----------------
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()

        print(f"{src} → {dst}")

        # -------------- PORT SCAN DETECTION --------------
        if TCP in packet:
            port = packet[TCP].dport
            port_scan_tracker[src].add(port)

            if len(port_scan_tracker[src]) > 25:
                print(f"\n[!! ALERT] Port Scan detected from {src}\n")

        # -------------- DOS DETECTION ---------------------
        dos_tracker[src].append(now)
        dos_tracker[src] = [t for t in dos_tracker[src] if now - t < 5]

        if len(dos_tracker[src]) > PACKET_LIMIT:
            print(f"\n[!! ALERT] DoS-like traffic from {src}\n")

    # -------------- HTTP PAYLOAD CHECK ------------------
    if packet.haslayer("Raw"):
        detect_suspicious_http(packet["Raw"].load)


# -----------------------------------------------------
# START SNIFFER
# -----------------------------------------------------
sniff(
    iface="\\Device\\NPF_{346B4DA4-4BE6-4A3A-B570-53F2F66E6C1F}",
    filter="ip",
    prn=process_packet,
    store=False
)

