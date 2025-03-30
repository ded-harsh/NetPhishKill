# 🛡️ NetPhishKill - Auto-Blocking Network Sniffer for Phishing Domains

## 🔥 Real-time Network Monitoring & Phishing Domain Auto-Blocker 🔥

### NetPhishKill is a packet sniffer that detects and automatically blocks suspicious domains linked to phishing activities. It uses Scapy for packet sniffing and Windows Firewall rules to block detected threats. 🚀

## 🔹 Features

### ✅ Live Packet Sniffing - Monitors network traffic in real-time.
### ✅ Phishing Domain Detection - Identifies suspicious domains using a blocklist.
### ✅ Auto-Blocking - Instantly blocks phishing domains using Windows Firewall.
### ✅ Logging - Keeps a detailed log of flagged domains and blocked connections.

## 🔹 Installation

### 1️⃣ Install Dependencies

Make sure you have Python 3.8+ installed. Then install the required libraries:

```bash
pip install scapy requests
```

You also need Npcap for packet sniffing:🔗 [Download Npcap](https://nmap.org/download.html) and install it with WinPcap API compatibility enabled.

## 🔹 How to Use

### 1️⃣ Find Your Network Interface

Before running the script, find your network interface name:Run this in cmd (Command Prompt):
```bash
ipconfig
```
Look for your active network adapter (Wi-Fi or Ethernet) and note the name. DO NOT use raw device names like \Device\NPF_...

## 2️⃣ Run NetPhishKill
```bash
python netphishkill.py --iface "Wi-Fi"
```
Or if using Ethernet(default so not necessaru):
```bash
python netphishkill.py --iface "Ethernet"
```
### 🔹 If you get an interface not found error, double-check the name from ipconfig

## 🔹 How It Works

### 1️⃣ Monitors network packets for suspicious domains.
### 2️⃣ Checks each domain against a phishing blocklist.
### 3️⃣ If a match is found, adds the domain to Windows Firewall rules to block it.
### 4️⃣ Logs all flagged connections in netphishkill_log.txt.

## 🔹 Example Output
```
[ALERT 🚨] Suspicious Domain Detected: badphish.com
[BLOCKED 🛑] Added badphish.com to Windows Firewall
[LOG 📝] 192.168.1.9 attempted connection to badphish.com (Blocked)
```

## 🔹 Logs & Analysis

### All findings are logged in netphishkill_log.txt. 
### Review this file to check for blocked domains and suspicious activity.

## 🔹 Future Plans

### ✨ Integration with VirusTotal API for better phishing detection
### ✨ Automated removal of expired firewall rules
### ✨ Real-time notifications for blocked domains

## 🔹 Disclaimer

### This tool is for educational purposes only. 
### Use responsibly and only on systems you own or have permission to test. 🔥


