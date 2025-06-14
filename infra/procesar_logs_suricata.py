import json
import csv
import os
from kafka import KafkaProducer

# --- Configuración ---
LOG_PATH = "logs/eve.json"
CSV_PATH = "data/salida_sip.csv"
KAFKA_TOPIC = "alerts_Suricata"
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]

# --- Verifica que el archivo JSON exista ---
if not os.path.exists(LOG_PATH):
    print(f"[!] No se encontró {LOG_PATH}. Asegúrate de haber ejecutado una captura con Suricata.")
    exit(1)

# --- Inicializa productor Kafka ---
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

# --- Crea carpeta de destino si no existe ---
os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

# --- Procesamiento ---
with open(CSV_PATH, "w", newline="") as f_csv, open(LOG_PATH, "r") as f_json:
    writer = csv.writer(f_csv)
    writer.writerow(["timestamp", "src_ip", "dest_ip", "proto", "label", "alert_msg"])

    for line in f_json:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        timestamp = event.get("timestamp", "")
        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")
        proto = event.get("proto", "")
        alert = event.get("alert", None)

        if alert:
            label = 1
            alert_msg = alert.get("signature", "SIP Alert")
            print(f"[!] Tráfico anómalo detectado: {alert_msg} | IP: {src_ip}")

            # --- Enviar alerta a Kafka ---
            alerta = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "proto": proto,
                "alert_msg": alert_msg
            }
            producer.send(KAFKA_TOPIC, value=alerta)
        else:
            label = 0
            alert_msg = ""

        writer.writerow([timestamp, src_ip, dest_ip, proto, label, alert_msg])

# --- Finaliza conexión Kafka ---
producer.flush()
producer.close()

print(f"\n✅ CSV generado en: {CSV_PATH}")

# --- Limpieza del archivo JSON ---
try:
    open(LOG_PATH, "w").close()
    print(f"[✔] Contenido de {LOG_PATH} limpiado para próxima ejecución.")
except Exception as e:
    print(f"[!] Error al limpiar {LOG_PATH}: {e}")
