import os
import json
import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configuration file for dynamic rules
CONFIG_FILE = "firewall_config.json"

# Default rules
firewall_rules = {
    "whitelisted_ips": ["127.0.0.1"],  # Default trusted IPs
    "blocked_ips": ["192.168.1.100"],
    "blocked_ports": [80, 443],
    "blocked_protocols": ["ICMP"]
}

# Rate limiting parameters
RATE_LIMIT = 10  # Max packets allowed per IP per time window
TIME_WINDOW = 10  # Time window in seconds
packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

def load_rules():
    """Load rules dynamically from the configuration file."""
    global firewall_rules
    try:
        with open(CONFIG_FILE, "r") as file:
            firewall_rules = json.load(file)
            print("Firewall rules updated:", firewall_rules)
    except Exception as e:
        print(f"Error loading rules: {e}")

def log_packet(packet, reason):
    """Log blocked packets to a file."""
    with open("firewall_log.txt", "a") as log:
        log.write(f"Blocked: {packet.summary()} | Reason: {reason}\n")

def is_rate_limited(src_ip):
    """Check if the source IP exceeds the rate limit."""
    current_time = time.time()
    data = packet_counts[src_ip]
    elapsed_time = current_time - data["timestamp"]

    if elapsed_time > TIME_WINDOW:
        # Reset the count and timestamp after the time window
        packet_counts[src_ip] = {"count": 1, "timestamp": current_time}
        return False

    # Increment the count and check against the rate limit
    if data["count"] < RATE_LIMIT:
        packet_counts[src_ip]["count"] += 1
        return False

    # Exceeded the rate limit
    return True

def packet_handler(packet):
    """Handle each packet, applying filtering rules."""
    global firewall_rules

    if packet.haslayer(IP):  # Check if the packet is an IP packet
        src_ip = packet[IP].src

        # Allow whitelisted IPs
        if src_ip in firewall_rules.get("whitelisted_ips", []):
            print(f"Allowed (whitelisted) packet from {src_ip}")
            return

        # Apply rate limiting
        if is_rate_limited(src_ip):
            print(f"Blocked packet from {src_ip} (rate limit exceeded)")
            log_packet(packet, "Rate limit exceeded")
            return

        # Check if the source IP is blocked
        if src_ip in firewall_rules.get("blocked_ips", []):
            print(f"Blocked packet from {src_ip}")
            log_packet(packet, "Source IP is blocked")
            return

        # Check for protocol-specific blocking
        if "ICMP" in firewall_rules.get("blocked_protocols", []) and packet.haslayer(ICMP):
            print("Blocked ICMP packet")
            log_packet(packet, "Blocked ICMP protocol")
            return
        if "TCP" in firewall_rules.get("blocked_protocols", []) and packet.haslayer(TCP):
            print("Blocked TCP packet")
            log_packet(packet, "Blocked TCP protocol")
            return
        if "UDP" in firewall_rules.get("blocked_protocols", []) and packet.haslayer(UDP):
            print("Blocked UDP packet")
            log_packet(packet, "Blocked UDP protocol")
            return

        # Check for TCP or UDP port blocking
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            protocol = "TCP" if packet.haslayer(TCP) else "UDP"
            layer = TCP if packet.haslayer(TCP) else UDP
            dst_port = packet[layer].dport

            if dst_port in firewall_rules.get("blocked_ports", []):
                print(f"Blocked {protocol} packet to port {dst_port}")
                log_packet(packet, f"{protocol} packet to blocked port {dst_port}")
                return

        # Allow the packet if it doesn't match any blocking rule
        print(f"Allowed packet: {packet.summary()}")

    else:
        print("Non-IP packet")

def monitor_config():
    """Monitor the configuration file for changes and reload rules."""
    last_modified = None
    while True:
        try:
            current_modified = time.ctime(os.path.getmtime(CONFIG_FILE))
            if current_modified != last_modified:
                load_rules()
                last_modified = current_modified
        except FileNotFoundError:
            print("Configuration file not found. Waiting...")
        time.sleep(2)  # Check for updates every 2 seconds

if __name__ == "__main__":
    print("Starting firewall_sniffer with rate limiting...")

    # Load initial rules
    load_rules()

    # Start a thread to monitor the configuration file
    threading.Thread(target=monitor_config, daemon=True).start()

    # Start sniffing packets
    sniff(prn=packet_handler, store=0)
