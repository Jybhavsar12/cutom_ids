from scapy.all import sniff, IP

THRESHOLD_PACKET_SIZE = 1500  # bytes

def detect_large_packet(packet):
    if packet.haslayer(IP):
        size = len(packet)
        if size > THRESHOLD_PACKET_SIZE:
            print(f"[ALERT] Large packet detected: Size={size} bytes, {packet.summary()}")

def start_sniffing():
    print("Starting packet capture with anomaly detection...")
    sniff(prn=detect_large_packet, store=False,count=50, timeout=10)

if __name__ == "__main__":
    start_sniffing()
