from scapy.all import sniff, ARP

def arp_display(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1:  # who-has (request)
            return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
        if pkt[ARP].op == 2:  # is-at (response)
            return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

print("Sniffing ARP packets...")
sniff(prn=arp_display, filter="arp", store=0, count=0)
