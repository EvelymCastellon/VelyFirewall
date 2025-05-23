import json
import csv
import glob
import os
from kafka import KafkaProducer
from datetime import datetime
import logging
import re

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración de rutas y Kafka
LOG_DIR = "/home/evelym/Lab/VelyFirewall/logs"
KAFKA_BOOTSTRAP_SERVERS = 'kafka:9092'

# Listas de detección
BLACKLISTED_HOSTS = {
    "sospechoso.node.com",
    "spoofed-origin.com",
    "gt_no_valido1",
    "gt_no_valido2",
    "hacker-gateway.net"
}

VALID_SS7_COMMANDS = {
    "UpdateLocation",
    "CancelLocation",
    "SendRoutingInfoForSM",
    "SendRoutingInfoForLocationService",
    "ProvideSubscriberInfo",
    "InsertSubscriberData"
}

VALID_DIAMETER_COMMANDS = {
    "UpdateLocationRequest",
    "CancelLocationRequest",
    "AuthenticationInformationRequest",
    "InsertSubscriberDataRequest",
    "DeleteSubscriberDataRequest",
    "NotifyRequest"
}

VALID_DIAMETER_APPLICATIONS = {
    "16777251",  # S6a/S6d
    "16777252",  # S13/S13'
    "16777216"   # Base Diameter
}

SUSPICIOUS_IMEI_PATTERNS = [
    r"^\d{14}0$",  # IMEI terminando en 0
    r"123456789012345"  # IMEI patrón consecutivo
]

def get_latest_csv():
    """Obtiene el archivo CSV más reciente en el directorio de logs"""
    csv_files = glob.glob(os.path.join(LOG_DIR, "*.csv"))
    if not csv_files:
        return None
    return max(csv_files, key=os.path.getctime)

def connect_kafka():
    """Establece conexión con Kafka"""
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        logger.info("✅ Conexión a Kafka establecida")
        return producer
    except Exception as e:
        logger.error(f"❌ Error al conectar con Kafka: {str(e)}")
        raise

def publish_alert(producer, attack_ip, attack_type, details=None):
    """Publica una alerta en el topic de alerts"""
    alert = {
        "timestamp": datetime.now().isoformat(),
        "attack_ip": attack_ip,
        "attack_type": attack_type,
        "details": details or {}
    }
    try:
        producer.send('alerts', alert)
        logger.info(f"🚨 Alerta publicada: {json.dumps(alert, indent=2)}")
    except Exception as e:
        logger.error(f"Error al publicar alerta: {str(e)}")

def check_imei(imei):
    """Verifica si un IMEI es sospechoso"""
    if not imei:
        return False
    return any(re.match(pattern, imei) for pattern in SUSPICIOUS_IMEI_PATTERNS)

def analyze_ss7_row(row, producer):
    """Aplica reglas de detección para SS7"""
    origin_host = row.get("origin_host", "desconocido")
    cmd = row.get("cmd", "")
    imsi = row.get("imsi", "")
    imei = row.get("imei", "")
    msisdn = row.get("msisdn", "")

    # Regla 1: Host en lista negra
    if origin_host in BLACKLISTED_HOSTS:
        attack_type = "Comunicación desde host no autorizado"
        if cmd == "SendRoutingInfoForLocationService":
            attack_type = "SRI-LS desde fuente no autorizada"
        elif cmd == "SendRoutingInfoForSM":
            attack_type = "SRI-SM desde GT no válido"
        
        publish_alert(producer, origin_host, attack_type, {
            "protocol": "SS7",
            "command": cmd,
            "imsi": imsi
        })

    # Regla 2: Comando SS7 no válido
    if cmd and cmd not in VALID_SS7_COMMANDS:
        publish_alert(producer, origin_host, "Comando SS7 no válido", {
            "invalid_command": cmd,
            "imsi": imsi
        })

    # Regla 3: IMEI sospechoso
    if check_imei(imei):
        publish_alert(producer, origin_host, "IMEI sospechoso detectado", {
            "imei": imei,
            "imsi": imsi
        })

    # Regla 4: MSISDN no válido
    if msisdn and (not msisdn.isdigit() or len(msisdn) < 10):
        publish_alert(producer, origin_host, "MSISDN con formato inválido", {
            "msisdn": msisdn,
            "imsi": imsi
        })

    # Regla 5: Comando InsertSubscriberData sin autenticación previa
    if cmd == "InsertSubscriberData" and "auth_flag" not in row:
        publish_alert(producer, origin_host, "InsertSubscriberData sin autenticación", {
            "imsi": imsi,
            "command": cmd
        })

def analyze_diameter_row(row, producer):
    """Aplica reglas de detección para Diameter"""
    origin_host = row.get("origin_host", "desconocido")
    cmd = row.get("cmd", "")
    imsi = row.get("imsi", "")
    app_id = row.get("diameter_app_id", "")

    # Regla 1: Host en lista negra
    if origin_host in BLACKLISTED_HOSTS:
        attack_type = "Comunicación Diameter desde host no autorizado"
        if cmd == "UpdateLocationRequest":
            attack_type = "ULR desde fuente no autorizada"
        elif cmd == "AuthenticationInformationRequest":
            attack_type = "AIR desde fuente no autorizada"
        
        publish_alert(producer, origin_host, attack_type, {
            "protocol": "Diameter",
            "command": cmd,
            "imsi": imsi
        })

    # Regla 2: Comando Diameter no válido
    if cmd and not cmd.startswith("Diameter:"):
        publish_alert(producer, origin_host, "Comando Diameter mal formado", {
            "invalid_command": cmd,
            "imsi": imsi
        })
    elif cmd:
        diameter_cmd = cmd.split(":")[1]
        if diameter_cmd not in VALID_DIAMETER_COMMANDS:
            publish_alert(producer, origin_host, "Comando Diameter no válido", {
                "invalid_command": diameter_cmd,
                "imsi": imsi
            })

    # Regla 3: Aplicación Diameter no autorizada
    if app_id and app_id not in VALID_DIAMETER_APPLICATIONS:
        publish_alert(producer, origin_host, "Aplicación Diameter no autorizada", {
            "application_id": app_id,
            "imsi": imsi
        })

    # Regla 4: ULR sin AIR previo
    if cmd == "Diameter:UpdateLocationRequest":
        publish_alert(producer, origin_host, "Secuencia anormal: ULR sin AIR previo", {
            "imsi": imsi,
            "command": cmd
        })

def analyze_csv_file(csv_file, producer):
    """Analiza un archivo CSV línea por línea"""
    with open(csv_file, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            protocol = row.get("protocol", "SS7")
            
            if protocol == "SS7":
                analyze_ss7_row(row, producer)
            elif protocol == "Diameter":
                analyze_diameter_row(row, producer)

def main():
    """Función principal"""
    producer = None
    
    try:
        # Obtener el archivo CSV más reciente
        csv_file = get_latest_csv()
        if not csv_file:
            logger.error("❌ No se encontraron archivos CSV en el directorio de logs")
            return
        
        logger.info(f"📂 Analizando archivo: {csv_file}")
        
        # Conectar a Kafka
        producer = connect_kafka()
        
        # Procesar el archivo CSV
        analyze_csv_file(csv_file, producer)
        
        logger.info("✅ Análisis completado")
                
    except Exception as e:
        logger.error(f"💥 Error crítico: {str(e)}")
    finally:
        if producer:
            producer.flush()
            producer.close()
        logger.info("🔚 Proceso finalizado")

if __name__ == "__main__":
    main()
