from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dot11 import Dot11

# Dictionary to map IP and MAC addresses (for ARP)
IP_MAC_MAP = {}

# Dictionary to track wireless devices
MAC_DEVICES = {}

def process_packet(packet):
    """Process ARP packets to detect potential attacks."""
    if ARP in packet and packet[ARP].op == 2:  # Check for ARP reply
        src_IP = packet[ARP].psrc
        src_MAC = packet[Ether].src

        # Check if the IP address has changed for this MAC
        old_IP = IP_MAC_MAP.get(src_MAC)
        if old_IP and old_IP != src_IP:
            message = (f"\nPossible ARP attack detected!\n"
                       f"MAC {src_MAC} (previously {old_IP}) is pretending to be {src_IP}\n")
            print(message)
        else:
            # Save the MAC-IP mapping
            IP_MAC_MAP[src_MAC] = src_IP

def process_wifi_packet(packet):
    """Process Wi-Fi packets to detect new devices."""
    if packet.haslayer(Dot11):  # Check for 802.11 layer
        mac_address = packet[Dot11].addr2  # Source MAC address
        ssid = packet[Dot11].info.decode(errors="ignore") if hasattr(packet[Dot11], 'info') else "Unknown"

        # Check if this device has been seen before
        if mac_address and mac_address not in MAC_DEVICES:
            MAC_DEVICES[mac_address] = ssid
            print(f"New device detected: MAC {mac_address}, SSID: {ssid}")

if __name__ == "__main__":
    print("Starting packet sniffing...\n")
    try:
        # Start sniffing ARP packets
        sniff(filter="arp", store=0, prn=process_packet)  # For ARP

        # Start sniffing Wi-Fi packets (requires wireless interface in monitor mode)
        sniff(prn=process_wifi_packet, store=0)
    except PermissionError:
        print("Run the script with sudo/root privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")
