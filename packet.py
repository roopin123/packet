from scapy.all import sniff, IP, TCP, UDP, ICMP


def packetcapture(packet):
    if IP in packet:
        ipsrc = packet[IP].src
        ipdst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)
        elif proto == 17:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)
        elif proto == 1:
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            protocol = "OTHER"
            payload = b""

        print(
            f"Protocol :{protocol} | Source :{ipsrc} -> Destination :{ipdst}"
        )
        print(f"Payload: {payload[:20]}...")
        print("-" * 50)


interface = "eth0"
print(f"Starting packet sniffing on {interface}...")
sniff(iface=interface, prn=packetcapture, store=0)