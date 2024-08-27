from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

def get_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for iface in interfaces:
        print(f" - {iface}")
    return interfaces

def scan_wifi(iface):
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors="ignore") if packet[Dot11Elt].info else "<Hidden SSID>"
            bssid = packet[Dot11].addr2
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel", "Unknown")
            signal = getattr(packet, 'dBm_AntSignal', "Unknown")
            rates = stats.get("rates", [])

            if bssid not in networks:
                networks[bssid] = {
                    "SSID": ssid,
                    "Signal": signal,
                    "Channel": channel,
                    "Rates": rates
                }

    print("Scanning for Wi-Fi networks...")
    sniff(prn=packet_handler, iface=iface, timeout=10, store=False)

    for bssid, network in networks.items():
        print(f"Network SSID      : {network['SSID']}")
        print(f"BSSID             : {bssid}")
        print(f"Signal Strength   : {network['Signal']} dBm")
        print(f"Channel           : {network['Channel']}")
        print(f"Supported Rates   : {' '.join(map(str, network['Rates']))} Mbps")
        print("")

if __name__ == "__main__":
    interfaces = get_interfaces()
    iface = input("Enter the interface you want to use: ")
    if iface in interfaces:
        try:
            scan_wifi(iface)
        except PermissionError:
            print("Permission denied: Run the script with elevated privileges.")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Invalid interface selected.")
