from scapy.all import sniff, TCP
from utils.logger import logger

def detect_syn_flood(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        # SYN flag set, ACK flag not set
        if tcp_layer.flags == 'S':
            alert_msg = f"SYN packet detected: {packet.summary()}"
            print(f"[ALERT] {alert_msg}")
            logger.info(alert_msg)

def start_sniffing():
    print("Starting packet capture with signature detection...")
    sniff(prn=detect_syn_flood, store=False, count=50, timeout=10)

if __name__ == "__main__":
    start_sniffing()
