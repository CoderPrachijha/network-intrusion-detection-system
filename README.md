🚀 Network Intrusion Detection System (IDS) in Python
A real-time Network Intrusion Detection System (IDS) built using Python, Scapy, and Npcap for Windows.
This project captures live network packets and detects suspicious activity such as DoS-like traffic, port scans, and malicious HTTP payloads.

🔥 Features
✅ Real-time Packet Sniffing
Captures live incoming/outgoing packets from the active network interface using Scapy and Npcap.
✅ Port Scan Detection
Identifies multiple connection attempts to different ports from the same IP.
✅ DoS-like Traffic Detection
Flags high-frequency packets coming from a single IP within a short time window.
✅ Suspicious HTTP Payload Detection
Detects keywords commonly used in attacks:


SQL Injection → select, union, drop, or 1=1, '--


XSS → <script>, alert(


Brute-force/credential abuse → admin, password


✅ Windows-Compatible
Works with:


VS Code


Python 3.x


Npcap driver


Administrator permissions



🛠 Tech Stack
ComponentTechnologyLanguagePythonLibrariesScapy, Collections, ReOSWindows 10/11Packet DriverNpcapEditorVS Code (Administrator mode)

📂 Project Structure
IDS_Project/
│── ids_project.py        # Main IDS script
│── README.md             # Documentation
└── requirements.txt      # (optional)


⚙️ Installation & Setup
1. Install Python
Download Python 3.10+
https://www.python.org/downloads/
2. Install Npcap
Required for packet sniffing on Windows:
https://nmap.org/npcap/
⚠️ During installation, enable:


WinPcap API-compatible Mode


Restart your PC after installing Npcap.
3. Install Scapy
Open VS Code terminal:
pip install scapy

4. Run VS Code as Administrator
Packet sniffing requires admin permissions.
5. Run the IDS
python ids_project.py


🧠 How It Works
🔎 1. Packet Capture
Sniff live packets using:
sniff(iface="YOUR_INTERFACE", filter="ip", prn=process_packet)

⚠️ 2. Port Scan Detection
Tracks attempts to multiple ports from the same source.
port_scan_tracker[src].add(port)

🚨 3. DoS Attack Detection
Tracks packet frequency using timestamps.
🛡 4. HTTP Payload Inspection
Checks raw HTTP for SQLi/XSS keywords.

📸 Output Example
--- NETWORK IDS STARTED ---
Using interface: \Device\NPF_{346B4DA4-4BE6-4A3A-B570-53F2F66E6C1F}
Capturing packets...

[PACKET]
192.168.1.38 → 142.250.182.10

[!! ALERT] DoS-like traffic detected from 192.168.1.25

[ALERT] Suspicious HTTP content → select
Payload: select * from users where id=1 -- ...


🙌 Future Improvements


Add Machine Learning–based anomaly detection (Isolation Forest)


Build a web dashboard with Flask


Use PCAP file logging for offline analysis


Add more attack signatures (MITM, ARP spoofing, DNS poisoning)



📄 License
This project is open-source and available under the MIT License.

⭐ Show Your Support!
If you like this project, please ⭐ the repository — it helps a lot.

If you want, I can also create:
✔ A beautiful GitHub banner
✔ Project screenshots
✔ Badges (Python version, License, Stars)
✔ A short demo video script
Just say “Add badges” or “Make screenshots” or “Make GitHub description”.
