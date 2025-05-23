# alert_suricata_kafka.py

import pandas as pd
from kafka import KafkaProducer
import json
import time

# Configuración
CSV_PATH = "/home/evelym/Lab/VelyFirewall/infra/data/salida_sip.csv"
KAFKA_TOPIC = "alerts_Suricata"
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]  # o la IP del broker Docker

# Cargar CSV
df = pd.read_csv(CSV_PATH)

# Crear productor Kafka
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

# Procesar fila por fila
for _, row in df.iterrows():
    if row['label'] == 1:
        alerta = {
            "timestamp": row['timestamp'],
            "src_ip": row['src_ip'],
            "dest_ip": row['dest_ip'],
            "proto": row['proto'],
            "alert_msg": row['alert_msg'] if pd.notna(row['alert_msg']) else "Anomalía detectada por Suricata"
        }
        producer.send(KAFKA_TOPIC, value=alerta)
        print(f"[ALERTA ENVIADA] {alerta}")
        time.sleep(0.1)  # opcional: pequeña pausa para no saturar Kafka

producer.flush()
producer.close()
