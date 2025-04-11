from scapy.all import *
from scapy.layers.sctp import *

# Configuración de IP (¡Cambia las IPs según tu red!)
ip = IP(src="172.16.21.21", dst="172.16.21.1")  # Ejemplo

# Configuración SCTP (puerto DIAMETER: 3868)
sctp = SCTP(sport=3868, dport=3868)

# Cabecera DIAMETER (CER: Capabilities Exchange Request)
diameter_payload = (
    b"\x01\x00\x00\x28"  # Versión 1, Longitud 40 bytes, Flags 0x00, Command Code 257 (CER)
    b"\x80\x00\x01\x01"  # Application-ID: Diameter Base (0)
    b"\x00\x00\x00\x01"  # Hop-by-Hop Identifier
    b"\x00\x00\x00\x02"  # End-to-End Identifier
    # AVP Origin-Host (Code 264)
    b"\x00\x00\x01\x08\x00\x00\x00\x0Chost.example"
    # AVP Origin-Realm (Code 296)
    b"\x00\x00\x01\x28\x00\x00\x00\x0Drealm.example"
)

# Construir y enviar el paquete
packet = ip / sctp / Raw(load=diameter_payload)
send(packet, iface="eno2", verbose=1)  # ¡Cambia "ens33" a tu interfaz!
