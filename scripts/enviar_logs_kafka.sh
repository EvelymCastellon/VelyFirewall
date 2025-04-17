#!/bin/bash

# Directorio donde se guardan los logs
WATCH_DIR="/home/evelym/Lab/VelyFirewall/logs"
TOPIC="raw_logs"
CONTAINER_NAME="infra_kafka_1"
PROCESSED_LOG="$WATCH_DIR/.logs_enviados.txt"

# Crear archivo si no existe
touch "$PROCESSED_LOG"

echo "📡 Monitoreando carpeta: $WATCH_DIR"
echo "🧾 Enviando archivos nuevos al topic de Kafka (Docker): $TOPIC"

while true; do
    # Buscar archivos .json, .csv y .pcap
    for file in "$WATCH_DIR"/*.{json,csv,pcap}; do
        # Verifica si el archivo ya fue procesado
        if [[ -f "$file" && ! $(grep -Fx "$file" "$PROCESSED_LOG") ]]; then
            echo "🚀 Enviando $file a Kafka dentro del contenedor..."

            # Enviar archivo al contenedor Kafka
            cat "$file" | docker exec -i "$CONTAINER_NAME" /usr/bin/kafka-console-producer \
                --broker-list localhost:9092 \
                --topic "$TOPIC"

            echo "$file" >> "$PROCESSED_LOG"
            echo "✅ Archivo enviado: $file"
        fi
    done
    sleep 10
done
