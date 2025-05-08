from scapy.all import rdpcap
import pandas as pd
import random
from datetime import datetime
import os
import shutil

# Rutas
input_dir = "/home/evelym/Lab/VelyFirewall/logs"
output_dir = "/home/evelym/Lab/VelyFirewall/logs/almacenamiento"

# Buscar el primer archivo .pcap en la carpeta
pcap_files = [f for f in os.listdir(input_dir) if f.endswith(".pcap")]
if not pcap_files:
    print("No se encontraron archivos .pcap en el directorio.")
    exit()

pcap_path = os.path.join(input_dir, pcap_files[0])

# Cargar paquetes
packets = rdpcap(pcap_path)

# Lista de columnas para el CSV
columns = [
    '_time', 'c_timestamp', 'c_cggt', 'c_imsi', 'f_c_ossn_others', 'f_same_cggt_is_gmlc_oc',
    'f_same_cggt_is_gmlc_ossn', 'f_same_cggt_is_hlr_oc', 'f_same_cggt_is_hlr_ossn',
    'f_velocity_greater_than_1000', 'f_count_unloop_country_last_x_hours_ul',
    'f_count_gap_ok_sai_and_all_lu', 'f_one_cggt_multi_cdgt_psi', 'f_count_ok_cl_between2lu',
    'f_count_ok_dsd_between2lu', 'f_count_ok_fwsm_mo_between2lu', 'f_count_ok_fwsm_mt_between2lu',
    'f_count_ok_fwsm_report_between2lu', 'f_count_ok_fwsm_submit_between2lu',
    'f_count_ok_isd_between2lu', 'f_count_ok_prn_between2lu', 'f_count_ok_psi_between2lu',
    'f_count_ok_purge_ms_between2lu', 'f_count_ok_sai_between2lu', 'f_count_ok_si_between2lu',
    'f_count_ok_sri_between2lu', 'f_count_ok_srism_between2lu', 'f_count_ok_ul_between2lu',
    'f_count_ok_ulgprs_between2lu', 'f_count_ok_ussd_between2lu', 'f_frequent_ok_cl_between2lu',
    'f_frequent_ok_dsd_between2lu', 'f_frequent_ok_fwsm_mo_between2lu', 'f_frequent_ok_fwsm_mt_between2lu',
    'f_frequent_ok_fwsm_report_between2lu', 'f_frequent_ok_fwsm_submit_between2lu',
    'f_frequent_ok_isd_between2lu', 'f_frequent_ok_prn_between2lu', 'f_frequent_ok_psi_between2lu',
    'f_frequent_ok_purge_ms_between2lu', 'f_frequent_ok_sai_between2lu', 'f_frequent_ok_si_between2lu',
    'f_frequent_ok_sri_between2lu', 'f_frequent_ok_srism_between2lu', 'f_frequent_ok_ul_between2lu',
    'f_frequent_ok_ulgprs_between2lu', 'f_frequent_ok_ussd_between2lu'
]

# Lista blanca de nodos confiables simulada
hosts_confiables = {"trusted-host-1", "trusted-host-2", "diameter.core.local"}

# Simular datos para un paquete

def simulate_row(pkt):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    row = {
        '_time': now,
        'c_timestamp': now,
        'c_cggt': f"CGGT_{random.randint(1000, 9999)}",
        'c_imsi': f"{random.randint(100000000000000, 999999999999999)}",
        'f_c_ossn_others': random.choice([0, 1]),
        'f_same_cggt_is_gmlc_oc': random.choice([0, 1]),
        'f_same_cggt_is_gmlc_ossn': random.choice([0, 1]),
        'f_same_cggt_is_hlr_oc': random.choice([0, 1]),
        'f_same_cggt_is_hlr_ossn': random.choice([0, 1]),
        'f_velocity_greater_than_1000': random.choice([0, 1]),
        'f_count_unloop_country_last_x_hours_ul': random.randint(0, 10),
        'f_count_gap_ok_sai_and_all_lu': random.randint(0, 10),
        'f_one_cggt_multi_cdgt_psi': random.choice([0, 1]),
        'f_count_ok_cl_between2lu': random.randint(0, 5),
        'f_count_ok_dsd_between2lu': random.randint(0, 5),
        'f_count_ok_fwsm_mo_between2lu': random.randint(0, 5),
        'f_count_ok_fwsm_mt_between2lu': random.randint(0, 5),
        'f_count_ok_fwsm_report_between2lu': random.randint(0, 5),
        'f_count_ok_fwsm_submit_between2lu': random.randint(0, 5),
        'f_count_ok_isd_between2lu': random.randint(0, 5),
        'f_count_ok_prn_between2lu': random.randint(0, 5),
        'f_count_ok_psi_between2lu': random.randint(0, 5),
        'f_count_ok_purge_ms_between2lu': random.randint(0, 5),
        'f_count_ok_sai_between2lu': random.randint(0, 5),
        'f_count_ok_si_between2lu': random.randint(0, 5),
        'f_count_ok_sri_between2lu': random.randint(0, 5),
        'f_count_ok_srism_between2lu': random.randint(0, 5),
        'f_count_ok_ul_between2lu': random.randint(0, 5),
        'f_count_ok_ulgprs_between2lu': random.randint(0, 5),
        'f_count_ok_ussd_between2lu': random.randint(0, 5),
        'f_frequent_ok_cl_between2lu': random.choice([0, 1]),
        'f_frequent_ok_dsd_between2lu': random.choice([0, 1]),
        'f_frequent_ok_fwsm_mo_between2lu': random.choice([0, 1]),
        'f_frequent_ok_fwsm_mt_between2lu': random.choice([0, 1]),
        'f_frequent_ok_fwsm_report_between2lu': random.choice([0, 1]),
        'f_frequent_ok_fwsm_submit_between2lu': random.choice([0, 1]),
        'f_frequent_ok_isd_between2lu': random.choice([0, 1]),
        'f_frequent_ok_prn_between2lu': random.choice([0, 1]),
        'f_frequent_ok_psi_between2lu': random.choice([0, 1]),
        'f_frequent_ok_purge_ms_between2lu': random.choice([0, 1]),
        'f_frequent_ok_sai_between2lu': random.choice([0, 1]),
        'f_frequent_ok_si_between2lu': random.choice([0, 1]),
        'f_frequent_ok_sri_between2lu': random.choice([0, 1]),
        'f_frequent_ok_srism_between2lu': random.choice([0, 1]),
        'f_frequent_ok_ul_between2lu': random.choice([0, 1]),
        'f_frequent_ok_ulgprs_between2lu': random.choice([0, 1]),
        'f_frequent_ok_ussd_between2lu': random.choice([0, 1]),
    }
    return row

# Clasificación heurística

def clasificar_trafico(row):
    if row['f_count_ok_psi_between2lu'] > 3:
        return 1
    if row['f_count_ok_fwsm_mt_between2lu'] > 3:
        return 1
    if row['f_count_ok_srism_between2lu'] > 3:
        return 1
    if row['f_count_ok_sri_between2lu'] > 3:
        return 1
    if row['f_count_ok_purge_ms_between2lu'] > 2:
        return 1
    if row['f_velocity_greater_than_1000'] == 1:
        return 1
    if row['f_c_ossn_others'] == 1:
        return 1
    if row['f_frequent_ok_cl_between2lu'] == 1:
        return 0
    if row['f_same_cggt_is_hlr_ossn'] == 1:
        return 0
    return 0

# Generar y clasificar
rows = [simulate_row(pkt) for pkt in packets[:100]]
df = pd.DataFrame(rows, columns=columns)
df['label'] = df.apply(clasificar_trafico, axis=1)

# Guardar como CSV
csv_filename = os.path.splitext(pcap_files[0])[0] + ".csv"
csv_output_path = os.path.join(input_dir, csv_filename)
df.to_csv(csv_output_path, index=False)
print(f"Archivo CSV generado: {csv_output_path}")

# Mover el archivo .pcap original
shutil.move(pcap_path, os.path.join(output_dir, pcap_files[0]))
print(f"Archivo .pcap movido a {output_dir}")
