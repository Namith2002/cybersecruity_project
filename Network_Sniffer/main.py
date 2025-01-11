from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    """
    Callback function to process captured packets.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Other"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        
        print(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")
        if protocol == "TCP":
            print(f"  TCP Info: {packet[TCP].summary()}")
        elif protocol == "UDP":
            print(f"  UDP Info: {packet[UDP].summary()}")


def main():
    print("Starting network sniffer...")
    print("Press Ctrl+C to stop.\n")
    
    # Sniff packets on the network interface
    sniff(prn=packet_callback, filter="ip", store=False)


if __name__ == "__main__":
    main()
