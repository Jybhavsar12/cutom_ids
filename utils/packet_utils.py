from scapy.all import IP, TCP, UDP

def extract_features(packet):
    features = {}
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        features['protocol'] = ip_layer.proto
        features['packet_length'] = len(packet)
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        features['flags'] = tcp_layer.flags
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
    return features
