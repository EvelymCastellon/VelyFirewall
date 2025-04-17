#!/bin/bash

WATCH_DIR="/home/evelym/Lab/VelyFirewall/logs"
TOPIC="raw_logs"
CONTAINER_NAME="infra_kafka_1"
PROCESSED_LOG="$WATCH_DIR/.json_enviados.txt"

touch "$PROCESSED_LOG"

echo "📡 Monitoreando archivos .json en: $WATCH_DIR"
echo "🧾 Enviando a Kafka (Docker) – Topic: $TOPIC"

while true; do
    for file in "$WATCH_DIR"/*.json; do
        if [[ -f "$file" && ! $(grep -Fx "$file" "$PROCESSED_LOG") ]]; then
            echo "🚀 Enviando $file..."
            cat "$file" | docker exec -i "$CONTAINER_NAME" /usr/bin/kafka-console-producer \
                --broker-list localhost:9092 \
                --topic "$TOPIC"
            echo "$file" >> "$PROCESSED_LOG"
            echo "✅ JSON enviado: $file"
        fi
    done
    sleep 10
done
