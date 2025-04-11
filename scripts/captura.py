from scapy.all import *
from diameter import Diameter, AVP  # Importar tu módulo

def analizar(pkt):
    if Diameter in pkt:
        print(f"Comando Diameter detectado: {pkt[Diameter].command_code}")
        
        # Analizar AVPs
        avp = pkt[AVP]
        while avp:
            print(f"AVP {avp.avp_code} -> {avp.data.hex()}")
            avp = avp.payload

sniff(
    iface="eno2",
    filter="tcp port 3868 and host 172.16.21.21",
    prn=analizar
)

