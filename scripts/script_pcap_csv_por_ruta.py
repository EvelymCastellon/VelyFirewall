from scapy.all import rdpcap
import pandas as pd
import random
from datetime import datetime

# Solicitar al usuario la ruta del archivo pcap
pcap_path = input("Introduce la ruta del archivo .pcap a convertir: ").strip()

# Cargar paquetes
packets = rdpcap(pcap_path)

# Lista de columnas del CSV de ejemplo (sin 'label')
columns = [
    '_time', 'c_timestamp', 'c_cggt', 'c_imsi', 'f_c_ossn_others', 'f_same_cggt_is_gmlc_oc',
    'f_same_cggt_is_gmlc_ossn', 'f_same_cggt_is_hlr_oc', 'f_same_cggt_is_hlr_ossn',
    'f_velocity_greater_than_1000', 'f_count_unloop_country_last_x_hours_ul',
    'f_count_gap_ok_sai_and_all_lu', 'f_one_cggt_multi_cdgt_psi', 'f_count_ok_cl_between2lu',
    'f_count_ok_dsd_between2lu', 'f_count_ok_fwsm_mo_between2lu', 'f_count_ok_fwsm_mt_between2lu',
    'f_count_ok_fwsm_report_between2lu', 'f_count_ok_fwsm_submit_between2lu', 'f_count_ok_isd_between2lu',
    'f_count_ok_prn_between2lu', 'f_count_ok_psi_between2lu', 'f_count_ok_purge_ms_between2lu',
    'f_count_ok_sai_between2lu', 'f_count_ok_si_between2lu', 'f_count_ok_sri_between2lu',
    'f_count_ok_srism_between2lu', 'f_count_ok_ul_between2lu', 'f_count_ok_ulgprs_between2lu',
    'f_count_ok_ussd_between2lu', 'f_frequent_ok_cl_between2lu', 'f_frequent_ok_dsd_between2lu',
    'f_frequent_ok_fwsm_mo_between2lu', 'f_frequent_ok_fwsm_mt_between2lu',
    'f_frequent_ok_fwsm_report_between2lu', 'f_frequent_ok_fwsm_submit_between2lu',
    'f_frequent_ok_isd_between2lu', 'f_frequent_ok_prn_between2lu', 'f_frequent_ok_psi_between2lu',
    'f_frequent_ok_purge_ms_between2lu', 'f_frequent_ok_sai_between2lu', 'f_frequent_ok_si_between2lu',
    'f_frequent_ok_sri_between2lu', 'f_frequent_ok_srism_between2lu', 'f_frequent_ok_ul_between2lu',
    'f_frequent_ok_ulgprs_between2lu', 'f_frequent_ok_ussd_between2lu'
]

# Simular datos para un paquete
def simulate_row(pkt):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return {
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

# Crear el DataFrame con los datos simulados
rows = [simulate_row(pkt) for pkt in packets[:100]]  # limita a 100 paquetes
df = pd.DataFrame(rows, columns=columns)

# Guardar como CSV
output_file = "pcap_output_simulated.csv"
df.to_csv(output_file, index=False)
print(f"Archivo CSV generado: {output_file}")
