import json
import csv
import os

LOG_PATH = "logs/eve.json"
CSV_PATH = "data/salida_sip.csv"

# Verifica que el archivo JSON exista
if not os.path.exists(LOG_PATH):
    print(f"[!] No se encontró {LOG_PATH}. Asegúrate de haber ejecutado una captura con Suricata.")
    exit(1)

# Crea carpetas necesarias
os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

# Procesamiento
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
        else:
            label = 0
            alert_msg = ""

        writer.writerow([timestamp, src_ip, dest_ip, proto, label, alert_msg])

print(f"\n✅ CSV generado en: {CSV_PATH}")

# Limpia el contenido de eve.json sin eliminar el archivo
try:
    open(LOG_PATH, "w").close()
    print(f"[✔] Contenido de {LOG_PATH} limpiado para próxima ejecución.")
except Exception as e:
    print(f"[!] Error al limpiar {LOG_PATH}: {e}")
