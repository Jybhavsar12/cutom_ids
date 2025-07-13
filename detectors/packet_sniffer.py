from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
