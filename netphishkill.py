from scapy.all import sniff, DNS, DNSQR
import requests
import os
import platform

# OpenPhish Feed URL (Updated every few minutes)
OPENPHISH_URL = "https://openphish.com/feed.txt"

# Fetch latest phishing domains
def fetch_phishing_domains():
    try:
        response = requests.get(OPENPHISH_URL)
        if response.status_code == 200:
            return set(response.text.split("\n"))
    except Exception as e:
        print(f"[ERROR] Could not fetch phishing domains: {e}")
    return set()

# Load phishing domains at startup
PHISHING_DOMAINS = fetch_phishing_domains()

def alert_user(message):
    """ Sends a real-time alert to the console """
    print(f"\n[ALERT 🚨] {message}\n")

def block_domain(domain):
    """ Blocks a phishing domain by modifying the hosts file """
    hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts" if platform.system() == "Windows" else "/etc/hosts"
    try:
        with open(hosts_path, "a") as hosts_file:
            hosts_file.write(f"\n127.0.0.1 {domain}")
        alert_user(f"🔒 Blocked domain: {domain}")
    except Exception as e:
        print(f"[ERROR] Could not modify hosts file: {e}")

def analyze_packet(packet):
    """ Analyze DNS packets for phishing domains """
    if packet.haslayer(DNSQR):
        print(f"[DEBUG] DNS Query: {packet[DNSQR].qname.decode()}")
        domain = packet[DNSQR].qname.decode()[:-1]
        if domain in PHISHING_DOMAINS:
            alert_user(f"⚠️ PHISHING DETECTED! Blocking domain: {domain}")
            block_domain(domain)

# Start sniffing on all interfaces
alert_user("Starting Packet Sniffer with Auto-Blocking...")
sniff(prn=analyze_packet, store=False, iface="Ethernet 2", filter="udp or tcp", lfilter=lambda p: p.haslayer(DNSQR))

