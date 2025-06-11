"""
analyzer.py - Ağ trafiği (PCAP) dosyalarını analiz eden modül.
MITM (ARP spoofing), port tarama ve DDoS saldırılarını tespit eder.
"""

from collections import defaultdict, Counter
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.utils import rdpcap

def analyze_pcap(filepath):
    """Yüklenen pcap dosyasını analiz ederek MITM, Port Scan, DDoS gibi saldırıları tespit eder."""
    packets = rdpcap(filepath)
    alerts = []

    # MITM Tespiti (ARP Spoofing)
    arp_table = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

    for ip, macs in arp_table.items():
        if len(macs) > 1:
            alerts.append({
                'type': 'MITM / ARP Spoofing',
                'src_ip': ip,
                'dst_ip': 'Multiple MACs',
                'description': f'ARP spoofing detected for IP {ip} mapped to multiple MACs: {macs}'
            })

    # Port Tarama Tespiti
    scan_counter = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP].src
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            if flags == 'S':
                scan_counter[ip].add(dport)

    for ip, ports in scan_counter.items():
        if len(ports) > 50:
            alerts.append({
                'type': 'Port Scan',
                'src_ip': ip,
                'dst_ip': 'Multiple Targets',
                'description': f'High number of SYN packets to different ports from {ip}'
            })

    # Basit DDoS Tespiti
    ip_counter = Counter(pkt[IP].src for pkt in packets if pkt.haslayer(IP))
    for ip, count in ip_counter.items():
        if count > 1000:
            alerts.append({
                'type': 'Possible DDoS',
                'src_ip': ip,
                'dst_ip': 'Broadcast or Flood Target',
                'description': f'{count} packets sent from {ip} - possible flood attack'
            })

    return {
        'file': filepath,
        'total_packets': len(packets),
        'alerts': alerts
    }
