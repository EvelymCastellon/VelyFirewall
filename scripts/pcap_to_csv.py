import os
import shutil
import logging
import random
from datetime import datetime
from scapy.all import rdpcap
import pandas as pd
import ss7_rules  # Importación del módulo de reglas
from kafka import KafkaProducer
import json

# --- Configuración inicial ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("pcap_to_csv")

INPUT_DIR = "/home/evelym/Lab/VelyFirewall/logs"
OUTPUT_DIR = "/home/evelym/Lab/VelyFirewall/logs"
STORAGE_DIR = os.path.join(OUTPUT_DIR, "almacenamiento")
os.makedirs(STORAGE_DIR, exist_ok=True)

KAFKA_TOPIC_ALERTS = "alerts"
KAFKA_SERVERS = ["localhost:9092"]

# --- Inicializar productor Kafka ---
producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

# --- Features requeridas por el modelo (actualizadas) ---
REQUIRED_FEATURES = [
    'src_ip', 'hex_payload', '_time', 'c_timestamp', 'c_cggt', 'c_imsi',
    'f_c_ossn_others', 'f_same_cggt_is_gmlc_oc', 'f_same_cggt_is_gmlc_ossn',
    'f_same_cggt_is_hlr_oc', 'f_same_cggt_is_hlr_ossn', 'f_count_ok_cl_between2lu',
    'f_count_ok_psi_between2lu', 'f_velocity_greater_than_1000',
    'f_count_unloop_country_last_x_hours_ul', 'f_count_gap_ok_sai_and_all_lu',
    'f_count_ok_dsd_between2lu', 'f_count_ok_fwsm_mo_between2lu',
    'f_count_ok_fwsm_mt_between2lu', 'f_count_ok_fwsm_report_between2lu',
    'f_count_ok_fwsm_submit_between2lu', 'f_count_ok_isd_between2lu',
    'f_count_ok_prn_between2lu', 'f_count_ok_purge_ms_between2lu',
    'f_count_ok_sai_between2lu', 'f_count_ok_si_between2lu',
    'f_count_ok_sri_between2lu', 'f_count_ok_srism_between2lu',
    'f_count_ok_ul_between2lu', 'f_count_ok_ulgprs_between2lu',
    'f_count_ok_ussd_between2lu', 'f_frequent_ok_cl_between2lu',
    'f_frequent_ok_psi_between2lu', 'f_frequent_ok_dsd_between2lu',
    'f_frequent_ok_fwsm_mo_between2lu', 'f_frequent_ok_fwsm_mt_between2lu',
    'f_frequent_ok_fwsm_report_between2lu', 'f_frequent_ok_fwsm_submit_between2lu',
    'f_frequent_ok_isd_between2lu', 'f_frequent_ok_prn_between2lu',
    'f_frequent_ok_purge_ms_between2lu', 'f_frequent_ok_sai_between2lu',
    'f_frequent_ok_si_between2lu', 'f_frequent_ok_sri_between2lu',
    'f_frequent_ok_srism_between2lu', 'f_frequent_ok_ul_between2lu',
    'f_frequent_ok_ulgprs_between2lu', 'f_frequent_ok_ussd_between2lu',
    'f_ratio_cl_psi', 'f_high_activity_5min', 'f_one_cggt_multi_cdgt_psi',
    'f_msg_count_per_imsi', 'c_network_node_number'
]

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_realistic_features(imsi=None):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hex_payload = ''.join(random.choices('0123456789abcdef', k=40))
    network_node_number = "9999999999" if random.random() < 0.1 else str(random.randint(1000000000, 9999999999))
    base_features = {
        'src_ip': generate_random_ip(),
        'hex_payload': hex_payload,
        '_time': now,
        'c_timestamp': now,
        'c_cggt': f"CGGT_{random.randint(1000, 9999)}",
        'c_imsi': imsi if imsi else f"{random.randint(100000000000000, 999999999999999)}",
        'c_network_node_number': network_node_number,
        'f_velocity_greater_than_1000': random.choices([0, 1], weights=[0.8, 0.2])[0],
        'f_high_activity_5min': random.choices([0, 1], weights=[0.7, 0.3])[0],
        'f_ratio_cl_psi': round(random.uniform(0.1, 2.5), 2),
    }
    binary_features = {
        f: random.choices([0, 1], weights=[0.8, 0.2])[0]
        for f in REQUIRED_FEATURES if f.startswith('f_same_') or f.startswith('f_frequent_')
    }
    count_features = {
        f: random.randint(0, 5)
        for f in REQUIRED_FEATURES if f.startswith('f_count_') and '_between' in f
    }
    return {**base_features, **binary_features, **count_features}

def extract_ip_and_hex_payload(packet):
    try:
        hex_payload = packet.original.hex() if hasattr(packet, 'original') else ""
        if packet.haslayer('IP'):
            return packet['IP'].src, hex_payload
        elif packet.haslayer('IPv6'):
            return packet['IPv6'].src, hex_payload
    except:
        return generate_random_ip(), ""

# 👇 Función auxiliar para determinar qué amenaza se detectó
def detectar_amenaza_principal(features):
    if ss7_rules.is_flooding_attack(features): return "Flooding IMSI"
    if ss7_rules.is_unauthorized_node(features): return "Nodo no autorizado"
    if ss7_rules.is_send_routing_info_attack(features): return "Ataque SRI"
    if ss7_rules.is_location_tracking_attack(features): return "Seguimiento de ubicación"
    if ss7_rules.is_hlr_update_attack(features): return "Modificación no autorizada de HLR"
    if ss7_rules.is_spoofing_detected(features): return "Suplantación de nodo"
    if ss7_rules.is_roaming_bypass(features): return "Bypass de roaming"
    if ss7_rules.is_data_integrity_suspect(features): return "Integridad de datos sospechosa"
    if ss7_rules.is_malicious_traffic_pattern(features): return "Patrón malicioso detectado"
    if ss7_rules.is_blacklisted_ip(features): return "IP en lista negra"
    return "Anomalía SS7"

def enviar_alerta_kafka(ip, amenaza):
    mensaje = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "amenaza": amenaza
    }
    producer.send(KAFKA_TOPIC_ALERTS, value=mensaje)
    logger.info(f"[Kafka] Alerta enviada: {mensaje}")

def process_pcap(pcap_path: str):
    try:
        packets = rdpcap(pcap_path)
        logger.info(f"Procesando {len(packets)} paquetes de {os.path.basename(pcap_path)}")
        packets = packets[:1000]

        imsi_pool = [f"{random.randint(100000000000000, 999999999999999)}" for _ in range(100)]
        imsi_counter = {}

        rows = []
        for packet in packets:
            src_ip, hex_payload = extract_ip_and_hex_payload(packet)
            imsi = random.choice(imsi_pool)
            features = generate_realistic_features(imsi)

            imsi_counter[imsi] = imsi_counter.get(imsi, 0) + 1
            features['f_msg_count_per_imsi'] = imsi_counter[imsi]
            features['src_ip'] = src_ip
            features['hex_payload'] = hex_payload
            features['c_imsi'] = imsi

            label = ss7_rules.is_anomalous(features)
            features['label'] = label

            # 👇 Si es anómalo, enviar alerta al topic
            if label == 1:
                amenaza = detectar_amenaza_principal(features)
                enviar_alerta_kafka(src_ip, amenaza)

            rows.append(features)

        all_columns = REQUIRED_FEATURES + ['label']
        df = pd.DataFrame(rows, columns=all_columns)

        csv_filename = f"{datetime.now().strftime('%Y%m%d_%H%M')}_{os.path.splitext(os.path.basename(pcap_path))[0]}.csv"
        csv_path = os.path.join(OUTPUT_DIR, csv_filename)
        df.to_csv(csv_path, index=False)
        logger.info(f"CSV generado con etiquetas: {csv_path}")

        shutil.move(pcap_path, os.path.join(STORAGE_DIR, os.path.basename(pcap_path)))
        return csv_path

    except Exception as e:
        logger.error(f"Error procesando {pcap_path}: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        pcap_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".pcap")]
        if not pcap_files:
            logger.warning(f"No se encontraron archivos .pcap en {INPUT_DIR}")
            exit()
        for pcap_file in pcap_files:
            pcap_path = os.path.join(INPUT_DIR, pcap_file)
            process_pcap(pcap_path)
    except Exception as e:
        logger.critical(f"Error fatal: {str(e)}")
        exit(1)
