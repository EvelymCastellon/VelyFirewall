from scapy.all import *
from scapy.layers.sctp import *

# Configuración de IP (¡Ajusta las IPs!)
ip = IP(src="172.16.21.21", dst="172.16.21.1")

# Configuración SCTP (puerto M3UA/SS7: 2905)
sctp = SCTP(sport=2905, dport=2905)

# Cabecera M3UA (Transfer Message)
m3ua_payload = (
    b"\x01\x00\x01\x01"  # Versión 1, Clase: Transfer (1), Tip>
    b"\x00\x00\x00\x10"  # Longitud: 16 bytes
    b"\x00\x00\x00\x01"  # Network Appearance
    b"\x00\x00\x00\x01"  # Routing Context
    # Datos MTP3/SCCP (ejemplo)
    b"\x01\x02\x03\x04\x05\x06\x07\x08"
)

# Construir y enviar el paquete
packet = ip / sctp / Raw(load=m3ua_payload)
send(packet, iface="eno2", verbose=1)  # ¡Cambia la interfaz!
