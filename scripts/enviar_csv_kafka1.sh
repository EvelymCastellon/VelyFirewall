#!/bin/bash

WATCH_DIR="/home/evelym/Lab/VelyFirewall/logs"
TOPIC="raw_logs"
CONTAINER_NAME="infra-kafka-1"
PROCESSED_LOG="$WATCH_DIR/.csv_enviados.txt"

touch "$PROCESSED_LOG"

echo "📡 Buscando archivos .csv en: $WATCH_DIR"
echo "🧾 Enviando a Kafka – Topic: $TOPIC"

# Buscar archivos .csv no enviados
nuevos_csv=0
for file in "$WATCH_DIR"/*.csv; do
    if [[ -f "$file" && ! $(grep -Fx "$file" "$PROCESSED_LOG") ]]; then
        echo "🚀 Enviando $file..."
        cat "$file" | docker exec -i "$CONTAINER_NAME" /usr/bin/kafka-console-producer \
            --broker-list localhost:9092 \
            --topic "$TOPIC"
        echo "$file" >> "$PROCESSED_LOG"
        echo "✅ CSV enviado: $file"
        nuevos_csv=$((nuevos_csv + 1))
    fi
done

if [[ $nuevos_csv -eq 0 ]]; then
    echo "✔️ No hay archivos nuevos por enviar."
else
    echo "📤 Se enviaron $nuevos_csv archivo(s) nuevo(s) a Kafka."
fi

echo "🛑 Proceso finalizado."

