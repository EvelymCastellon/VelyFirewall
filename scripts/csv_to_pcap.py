import pandas as pd
from scapy.all import IP, UDP, Raw, wrpcap
import random

# Cargar el CSV original
df = pd.read_csv("Labeled_data.csv")
packets = []

# Solo usamos 100 filas para demo
for idx, row in df.head(100).iterrows():
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    dst_ip = f"10.0.0.{random.randint(1, 254)}"
    sport = random.randint(1024, 65535)
    dport = 2905  # Puerto típico para tráfico SS7 simulado

    payload = f"IMSI:{row['c_imsi']}, CGGT:{row['c_cggt']}, TIMESTAMP:{row['c_timestamp']}"
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload.encode())

    packets.append(pkt)

# Guardar a archivo pcap
wrpcap("synthetic_ss7_traffic.pcap", packets)
print("✅ Archivo PCAP generado: synthetic_ss7_traffic.pcap")
