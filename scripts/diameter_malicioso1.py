from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.sctp import SCTP
import random
import time

# Lista de IPs maliciosas simuladas
malicious_ips = ["192.168.100.1", "192.168.100.2", "192.168.100.3"]

# Tipos de ataque simulados con sus configuraciones
attack_types = {
    'flood': lambda: (IP(src=random.choice(malicious_ips)), 0.01),
    'invalid_avp': lambda: (IP(), 0.5),
    'session_replay': lambda: (IP(), 1),
    'abort_session': lambda: (IP(), 0.5)
}

print("💥 Opciones de ataque disponibles:", list(attack_types.keys()))
tipo = input("⚠️  Selecciona tipo de ataque: ").strip()

if tipo not in attack_types:
    print("❌ Tipo de ataque no válido.")
    exit(1)

dst_ip = input("🌐 Dirección IP destino: ").strip()

# Construcción y envío de paquetes
ip_pkt, delay = attack_types[tipo]()
ip_pkt.dst = dst_ip

for i in range(10):
    pkt = ip_pkt / TCP(sport=3868, dport=3868) / Raw(load=b'\x01\x00\x00\x01')
    send(pkt, verbose=0)
    print(f"🚀 Paquete {i+1} enviado ({tipo}) a {dst_ip}")
    time.sleep(delay)

print("✅ Ataque simulado finalizado.")
