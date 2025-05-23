#!/bin/bash

WATCH_DIR="/home/evelym/Lab/VelyFirewall/logs"
TOPIC="raw_logs"
CONTAINER_NAME="infra-kafka-1"
PROCESSED_LOG="$WATCH_DIR/.csv_enviados.txt"

touch "$PROCESSED_LOG"

echo "📡 Buscando archivos .csv en: $WATCH_DIR"
echo "🧾 Enviando a Kafka – Topic: $TOPIC"

nuevos_csv=0
for file in "$WATCH_DIR"/*.csv; do
    if [[ -f "$file" && ! $(grep -Fx "$file" "$PROCESSED_LOG") ]]; then
        echo "🚀 Enviando $file..."
        # Enviar el CSV completo como un solo mensaje usando docker exec
        docker exec -i "$CONTAINER_NAME" bash -c \
            "cat < /dev/stdin | /usr/bin/kafka-console-producer --broker-list localhost:9092 --topic $TOPIC" < "$file"
        
        if [ $? -eq 0 ]; then
            echo "$file" >> "$PROCESSED_LOG"
            echo "✅ CSV enviado: $file"
            nuevos_csv=$((nuevos_csv + 1))
        else
            echo "❌ Error al enviar $file"
        fi
    fi
done

if [[ $nuevos_csv -eq 0 ]]; then
    echo "✔️ No hay archivos nuevos por enviar."
else
    echo "📤 Se enviaron $nuevos_csv archivo(s) nuevo(s) a Kafka."
fi

echo "🛑 Proceso finalizado."
