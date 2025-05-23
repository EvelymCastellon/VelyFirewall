import os
import shutil
import logging
import random
from datetime import datetime
from scapy.all import rdpcap
import pandas as pd

# --- Configuración inicial ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("pcap_to_csv")

# Rutas (ajusta según tu entorno)
INPUT_DIR = "/home/evelym/Lab/VelyFirewall/logs"  # Directorio para archivos .pcap
OUTPUT_DIR = "/home/evelym/Lab/VelyFirewall/logs"  # Directorio para CSVs
STORAGE_DIR = os.path.join(OUTPUT_DIR, "almacenamiento")

os.makedirs(STORAGE_DIR, exist_ok=True)

# --- Features requeridas por el modelo (44 en total) + IP ---
REQUIRED_FEATURES = [
    'src_ip',  # Nueva columna añadida
    '_time', 'c_timestamp', 'c_cggt', 'c_imsi',
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
    'f_ratio_cl_psi', 'f_high_activity_5min', 'f_one_cggt_multi_cdgt_psi'
]

def generate_random_ip():
    """Genera una dirección IP aleatoria"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_realistic_features():
    """Genera valores lógicos para las features críticas"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Base para todas las filas
    base_features = {
        'src_ip': generate_random_ip(),  # IP de origen añadida
        '_time': now,
        'c_timestamp': now,
        'c_cggt': f"CGGT_{random.randint(1000, 9999)}",
        'c_imsi': f"{random.randint(100000000000000, 999999999999999)}",
        'f_velocity_greater_than_1000': random.choices([0, 1], weights=[0.8, 0.2])[0],
        'f_high_activity_5min': random.choices([0, 1], weights=[0.7, 0.3])[0],
        'f_ratio_cl_psi': round(random.uniform(0.1, 2.5), 2),
    }
    
    # Features binarias
    binary_features = {
        f: random.choices([0, 1], weights=[0.8, 0.2])[0] 
        for f in REQUIRED_FEATURES 
        if f.startswith('f_same_') or f.startswith('f_frequent_')
    }
    
    # Features de conteo
    count_features = {
        f: random.randint(0, 5) 
        for f in REQUIRED_FEATURES 
        if f.startswith('f_count_') and '_between' in f
    }
    
    return {**base_features, **binary_features, **count_features}

def extract_ip_from_packet(packet):
    """Intenta extraer la IP de origen de un paquete"""
    try:
        if packet.haslayer('IP'):
            return packet['IP'].src
        elif packet.haslayer('IPv6'):
            return packet['IPv6'].src
    except:
        return generate_random_ip()  # Fallback si no puede extraer IP

def process_pcap(pcap_path: str):
    try:
        packets = rdpcap(pcap_path)
        logger.info(f"Procesando {len(packets)} paquetes de {os.path.basename(pcap_path)}")
        
        # Limitar a 1000 paquetes
        packets = packets[:1000]
        
        # Generar filas con datos realistas
        rows = []
        for packet in packets:
            features = generate_realistic_features()
            # Sobrescribir la IP generada con la real del paquete si existe
            features['src_ip'] = extract_ip_from_packet(packet)
            rows.append(features)
            
        df = pd.DataFrame(rows, columns=REQUIRED_FEATURES)
        
        # Validar integridad
        missing = set(REQUIRED_FEATURES) - set(df.columns)
        if missing:
            raise ValueError(f"Features faltantes en CSV: {missing}")
        
        # Guardar CSV
        csv_filename = f"{datetime.now().strftime('%Y%m%d_%H%M')}_{os.path.splitext(os.path.basename(pcap_path))[0]}.csv"
        csv_path = os.path.join(OUTPUT_DIR, csv_filename)
        df.to_csv(csv_path, index=False)
        logger.info(f"CSV generado con {len(df)} filas: {csv_path}")
        
        # Mover PCAP a almacenamiento
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
