Packet Sniffer for ARP and Wi-Fi Monitoring
Overview
This Python script is designed to monitor network traffic and detect potential security issues such as ARP spoofing attacks and identify new devices in a Wi-Fi network. It uses the scapy library to sniff packets and analyze ARP requests and replies, as well as 802.11 Wi-Fi packets.

Key Features:
ARP Spoofing Detection: Monitors ARP replies and checks for discrepancies in the IP-to-MAC address mapping. If an IP address associated with a MAC address changes unexpectedly, it flags this as a potential ARP spoofing attack.
Wi-Fi Device Detection: Captures Wi-Fi packets to identify new devices that join the network, displaying their MAC address and SSID.
Installation
Clone the Repository:

bash
Копіювати код
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
Install Dependencies: This script requires the scapy library, which can be installed using pip:

bash
Копіювати код
pip install scapy
Run the Script: Ensure that you have root or sudo privileges to allow for sniffing network traffic.

bash
Копіювати код
sudo python3 sniffer.py
Usage
When you run the script, it will:

Start sniffing for ARP packets to detect possible ARP attacks.
Start sniffing for Wi-Fi packets and display new devices joining the network.
ARP Spoofing Detection
The script will display messages if it detects an ARP attack:

php
Копіювати код
Possible ARP attack detected!
MAC <MAC_ADDRESS> (previously <OLD_IP>) is pretending to be <NEW_IP>
Wi-Fi Device Detection
The script will print information about any new devices detected:

arduino
Копіювати код
New device detected: MAC <MAC_ADDRESS>, SSID: <SSID>
Requirements
Python 3.x
scapy library
Root or sudo privileges (necessary for packet sniffing)
Recommendations for Running
Run as Root: Ensure you have root access to capture network packets. Use sudo on Linux/macOS or run the script as Administrator on Windows with appropriate privileges.

Monitor Mode: For detecting Wi-Fi devices, you need to set your wireless adapter into monitor mode. This mode allows you to listen to all Wi-Fi traffic in range.

Linux:

Use tools like airmon-ng to enable monitor mode on your wireless interface.
bash
Копіювати код
sudo airmon-ng start wlan0
MacOS:

Typically, MacOS should already support monitor mode for wireless interfaces.
Run on a Dedicated Device: If you're using the script for a security or monitoring purpose, consider running it on a dedicated machine or device that doesn't interfere with your regular work.

Legal and Ethical Considerations: Ensure you have permission to monitor the network traffic, as sniffing and intercepting packets without consent can be illegal in some jurisdictions.

Troubleshooting
Permission Issues: If you encounter a PermissionError, ensure you're running the script with root/sudo privileges.
No New Devices Detected: Make sure your wireless adapter is in monitor mode and is within range of devices broadcasting Wi-Fi packets.
Contributing
Feel free to fork the repository, submit issues, and contribute improvements or bug fixes. Pull requests are welcome!

Additional Recommendations:
Add Logging: Consider implementing a logging system (e.g., using Python’s logging module) to log detected events to a file for later analysis.
Enhance Detection Mechanisms: You can extend the ARP spoofing detection to include timestamp checks, logging suspicious behavior over time, or integrating more sophisticated attack detection mechanisms.
Cross-Platform Testing: While the script should work on Linux and macOS, test it across different platforms and document any platform-specific requirements.
