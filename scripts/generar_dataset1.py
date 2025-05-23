# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
from faker import Faker
from datetime import datetime
import json
import random
import os

# --- Configuración Mejorada ---
NUM_SAMPLES = 10000        # Número inicial de muestras
RANDOM_SEED = 42
FRAUD_RATIO = 0.12         # 12% de casos de fraude iniciales
DESIRED_FRAUD_RATIO = 0.15 # Objetivo final ~15% fraudes
NOISE_RATIO = 0.05         # 5% de valores anómalos

np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)
fake = Faker()

# Ruta de salida
OUTPUT_PATH = "/home/evelym/Lab/VelyFirewall/data/"
os.makedirs(OUTPUT_PATH, exist_ok=True)

# Columnas según el esquema original + derivadas
COLUMNS = [
    ',_time', 'c_timestamp', 'c_cggt', 'c_imsi',
    'f_c_ossn_others', 'f_same_cggt_is_gmlc_oc', 'f_same_cggt_is_gmlc_ossn',
    'f_same_cggt_is_hlr_oc', 'f_same_cggt_is_hlr_ossn', 'f_velocity_greater_than_1000',
    'f_count_unloop_country_last_x_hours_ul', 'f_count_gap_ok_sai_and_all_lu',
    'f_one_cggt_multi_cdgt_psi', 'f_count_ok_cl_between2lu', 'f_count_ok_psi_between2lu',
    'f_count_ok_dsd_between2lu', 'f_count_ok_fwsm_mo_between2lu', 'f_count_ok_fwsm_mt_between2lu',
    'f_count_ok_fwsm_report_between2lu', 'f_count_ok_fwsm_submit_between2lu', 'f_count_ok_isd_between2lu',
    'f_count_ok_prn_between2lu', 'f_count_ok_purge_ms_between2lu', 'f_count_ok_sai_between2lu',
    'f_count_ok_si_between2lu', 'f_count_ok_sri_between2lu', 'f_count_ok_srism_between2lu',
    'f_count_ok_ul_between2lu', 'f_count_ok_ulgprs_between2lu', 'f_count_ok_ussd_between2lu',
    'f_frequent_ok_cl_between2lu', 'f_frequent_ok_psi_between2lu', 'f_frequent_ok_dsd_between2lu',
    'f_frequent_ok_fwsm_mo_between2lu', 'f_frequent_ok_fwsm_mt_between2lu',
    'f_frequent_ok_fwsm_report_between2lu', 'f_frequent_ok_fwsm_submit_between2lu',
    'f_frequent_ok_isd_between2lu', 'f_frequent_ok_prn_between2lu', 'f_frequent_ok_purge_ms_between2lu',
    'f_frequent_ok_sai_between2lu', 'f_frequent_ok_si_between2lu', 'f_frequent_ok_sri_between2lu',
    'f_frequent_ok_srism_between2lu', 'f_frequent_ok_ul_between2lu', 'f_frequent_ok_ulgprs_between2lu',
    'f_frequent_ok_ussd_between2lu', 'f_ratio_cl_psi', 'f_high_activity_5min', 'label'
]

def generate_row():
    c_cggt = random.choice([11111111, 22222222, 33333333])
    imsi = f"242{fake.msisdn()[3:]:0<12}"
    is_fraud = 1 if np.random.rand() < FRAUD_RATIO else 0
    overlap = np.random.beta(1 + 2*is_fraud, 4)

    night_bias = 0.7 if is_fraud else 0.3
    night_prob = night_bias / 8
    day_prob = (1 - night_bias) / 16
    hour_probs = [day_prob]*16 + [night_prob]*8
    hour = np.random.choice(range(24), p=hour_probs)
    fake_time = fake.date_time_between(start_date="-1y", end_date="now").replace(hour=hour)
    time_str = fake_time.strftime("%Y-%m-%dT%H:%M:%S.000+01:00")

    row = {
        ',_time': time_str,
        'c_timestamp': int(datetime.now().timestamp()),
        'c_cggt': c_cggt,
        'c_imsi': imsi,
        'f_c_ossn_others': np.random.choice([0,1], p=[0.9,0.1]),
        'f_same_cggt_is_gmlc_oc': np.random.choice([0,1], p=[0.9,0.1]),
        'f_same_cggt_is_gmlc_ossn': np.random.choice([0,1], p=[0.9,0.1]),
        'f_same_cggt_is_hlr_oc': np.random.choice([0,1], p=[0.2,0.8]) if c_cggt==33333333 else np.random.choice([0,1], p=[0.9,0.1]),
        'f_same_cggt_is_hlr_ossn': np.random.choice([0,1], p=[0.2,0.8]) if c_cggt==33333333 else np.random.choice([0,1], p=[0.9,0.1])
    }

    lam0, lam1 = 1, 4 + overlap*2
    row['f_count_ok_cl_between2lu'] = np.random.poisson(lam=lam0 if is_fraud==0 else lam1)
    row['f_count_ok_psi_between2lu'] = np.random.poisson(lam=(lam0*1.5) if is_fraud==0 else (lam1*1.5))
    row['f_velocity_greater_than_1000'] = np.random.choice([0,1], p=([0.99,0.01] if is_fraud==0 else [0.97,0.03]))

    for feature in COLUMNS:
        if feature not in row:
            if feature.startswith('f_count'):
                row[feature] = 0
            elif feature.startswith('f_frequent'):
                row[feature] = 0.0

    cl, psi = row['f_count_ok_cl_between2lu'], row['f_count_ok_psi_between2lu']
    row['f_ratio_cl_psi'] = np.log((cl+1e-5)/(psi+1e-5))
    row['f_high_activity_5min'] = np.random.choice([0,1], p=([0.95,0.05] if is_fraud==0 else [0.7,0.3]))

    if np.random.rand() < NOISE_RATIO:
        noise_feats = random.sample([c for c in COLUMNS if c.startswith('f_')], 2)
        for feat in noise_feats:
            val = row.get(feat, 0)
            if 'count' in feat:
                row[feat] = val + np.random.randint(3,10)
            else:
                row[feat] = np.clip(val + np.random.uniform(-0.2,0.2), 0, 1)

    row['label'] = is_fraud
    return row

# Generar dataset
if __name__ == '__main__':
    data = [generate_row() for _ in range(NUM_SAMPLES)]
    extra = int(NUM_SAMPLES*(DESIRED_FRAUD_RATIO - FRAUD_RATIO)/(1-DESIRED_FRAUD_RATIO))
    extra_rows = [generate_row() for _ in range(extra)]
    for r in extra_rows: r['label'] = 1

    df = pd.DataFrame(data + extra_rows)
    df.to_csv(os.path.join(OUTPUT_PATH, "synthetic_dataset_v4_adjusted.csv"), index=False, float_format="%.6f")

    meta = {
        "generated_at": datetime.now().isoformat(),
        "num_samples": len(df),
        "fraud_ratio": df['label'].mean(),
        "noise_ratio": NOISE_RATIO
    }

    with open(os.path.join(OUTPUT_PATH, "metadata_v4_adjusted.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"✅ Dataset generado: {len(df)} muestras")
    print(f"📊 Ratio de fraude final: {df['label'].mean():.2%}")
    print(f"📁 Archivos guardados en: {OUTPUT_PATH}")

