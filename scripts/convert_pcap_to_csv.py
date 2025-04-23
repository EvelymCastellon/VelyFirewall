from scapy.all import rdpcap
import pandas as pd
import os

def convertir_pcap_a_csv():
    # Solicita al usuario el nombre del archivo
    pcap_file = input("Introduce la ruta del archivo .pcap que deseas convertir: ").strip()

    # Verifica que el archivo exista
    if not os.path.exists(pcap_file):
        print(f"❌ El archivo '{pcap_file}' no existe.")
        return

    # Cargar paquetes
    print("🔄 Cargando y procesando paquetes...")
    packets = rdpcap(pcap_file)

    # Extraer información
    data = []
    for pkt in packets:
        pkt_info = {
            "timestamp": pkt.time,
            "src": pkt[0].src if hasattr(pkt[0], "src") else "N/A",
            "dst": pkt[0].dst if hasattr(pkt[0], "dst") else "N/A",
            "protocol": pkt[0].name,
        }

        # Etiquetado simple: basado en protocolo
        if "SS7" in pkt_info["protocol"] or "Diameter" in pkt_info["protocol"]:
            pkt_info["label"] = "anómalo"
        else:
            pkt_info["label"] = "normal"

        data.append(pkt_info)

    # Crear DataFrame
    df = pd.DataFrame(data)

    # Crear nombre de salida .csv
    csv_file = os.path.splitext(pcap_file)[0] + "_etiquetado.csv"
    df.to_csv(csv_file, index=False)

    print(f"✅ Conversión completa. Archivo guardado en: {csv_file}")

if __name__ == "__main__":
    convertir_pcap_a_csv()
