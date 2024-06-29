from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {packet.summary()}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            if packet[TCP].payload:
                print(f"Payload: {str(bytes(packet[TCP].payload))}")
        
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            if packet[UDP].payload:
                print(f"Payload: {str(bytes(packet[UDP].payload))}")
        
        elif ICMP in packet:
            print("Protocol: ICMP")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")
            if packet[ICMP].payload:
                print(f"Payload: {str(bytes(packet[ICMP].payload))}")

        else:
            print(f"Protocol: Other ({ip_layer.proto})")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(filter="", prn=packet_callback, store=0)
