# sniffer.py - Basic Network Sniffer for Windows 11

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto_name = "Other"
            sport = dport = None

        print(f"[+] {src_ip} --> {dst_ip} | {proto_name}", end="")
        if sport and dport:
            print(f" (Port {sport}->{dport})")
        else:
            print()

# Start sniffing (interface auto-detected)
if __name__ == "__main__":
    print("🔍 Starting sniffer on Windows 11... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, count=0)