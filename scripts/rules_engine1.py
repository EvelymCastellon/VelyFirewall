import redis
import json
from kafka import KafkaConsumer, KafkaProducer
from datetime import datetime

# Conexión a Redis
r = redis.Redis(host='localhost', port=6379, db=0)

# Kafka
consumer = KafkaConsumer(
    'raw_logs',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda m: safe_deserialize(m),
    auto_offset_reset='earliest',
    enable_auto_commit=True,
    group_id='rules-engine-group'
)

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

def safe_deserialize(message):
    try:
        decoded = message.decode('utf-8')
        if not decoded.strip():  # Verifica mensaje vacío
            print("⚠️ Mensaje vacío recibido. Ignorado.")
            return None
        return json.loads(decoded)
    except json.JSONDecodeError:
        print("❌ Error al decodificar JSON. Mensaje inválido:")
        print(message)
        return None

def publish_alert(alert):
    producer.send('alerts', alert)
    print("🚨 Alerta generada:", alert)

# Lista negra
blacklisted_hosts = {"sospechoso.node.com", "spoofed-origin.com"}

# Reglas
def rule_flooding_sri(imsi):
    key = f"sri:{imsi}"
    now = datetime.now()
    r.zadd(key, {now.timestamp(): now.timestamp()})
    r.expire(key, 60)
    requests = r.zrangebyscore(key, now.timestamp() - 60, now.timestamp())
    if len(requests) > 10:
        publish_alert({"alert": "Flooding SRI detectado", "imsi": imsi})

def rule_imsi_catching(imsi, origin_host):
    if origin_host in blacklisted_hosts:
        publish_alert({"alert": "IMSI Catching sospechoso", "imsi": imsi, "host": origin_host})

def rule_spoofing(imsi, origin_host):
    key = f"origin:{imsi}"
    prev_host = r.get(key)
    if prev_host and prev_host.decode() != origin_host:
        publish_alert({
            "alert": "Spoofing IMSI detectado",
            "imsi": imsi,
            "prev_host": prev_host.decode(),
            "current_host": origin_host
        })
    r.set(key, origin_host, ex=300)

def rule_replay(imsi, cmd, timestamp):
    key = f"replay:{imsi}:{cmd}"
    if r.get(key):
        publish_alert({"alert": "Posible Replay detectado", "imsi": imsi, "cmd": cmd})
    r.set(key, timestamp, ex=60)

def rule_unusual_location(imsi, location):
    key = f"location:{imsi}"
    known = r.smembers(key)
    if known and location.encode() not in known:
        publish_alert({
            "alert": "Ubicación inesperada para IMSI",
            "imsi": imsi,
            "location": location
        })
    r.sadd(key, location)
    r.expire(key, 3600)

print("🔍 Iniciando rules_engine.py... escuchando raw_logs")

# Bucle de monitoreo
for msg in consumer:
    if msg.value is None:
        continue  # Ignorar mensajes no válidos

    data = msg.value

    # Verificar el tipo de 'data' y proceder en consecuencia
    if isinstance(data, dict):
        # Extraer valores de un diccionario
        imsi = data.get("imsi", "desconocido")
        origin_host = data.get("origin_host", "desconocido")
        cmd = data.get("cmd", "")
        timestamp = data.get("timestamp", datetime.now().isoformat())
        location = data.get("location", "desconocido")

        # Aplicar reglas
        rule_flooding_sri(imsi)
        rule_imsi_catching(imsi, origin_host)
        rule_spoofing(imsi, origin_host)
        rule_replay(imsi, cmd, timestamp)
        rule_unusual_location(imsi, location)

    elif isinstance(data, list):
        # Si es una lista, iterar sobre cada elemento
        for item in data:
            if isinstance(item, dict):
                imsi = item.get("imsi", "desconocido")
                origin_host = item.get("origin_host", "desconocido")
                cmd = item.get("cmd", "")
                timestamp = item.get("timestamp", datetime.now().isoformat())
                location = item.get("location", "desconocido")

                # Aplicar reglas
                rule_flooding_sri(imsi)
                rule_imsi_catching(imsi, origin_host)
                rule_spoofing(imsi, origin_host)
                rule_replay(imsi, cmd, timestamp)
                rule_unusual_location(imsi, location)
            else:
                print(f"⚠️ Elemento en la lista no es un diccionario: {item}")
    else:
        print("⚠️ Formato de datos inesperado:", type(data))
