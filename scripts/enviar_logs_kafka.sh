#!/bin/bash

# Ruta del directorio donde se guardan los logs JSON
WATCH_DIR="/home/evelym/Lab/VelyFirewall/logs"
# Ruta del productor de Kafka
KAFKA_BIN_DIR="$HOME/kafka/kafka_2.13-3.6.1/bin"
# Topic de Kafka al que se enviarán los mensajes
TOPIC="logs"
# Archivo donde se guarda la lista de archivos ya enviados
PROCESSED_LOG="$WATCH_DIR/.logs_enviados.txt"

# Crear archivo si no existe
touch "$PROCESSED_LOG"

echo "📡 Monitoreando carpeta: $WATCH_DIR"
echo "🧾 Enviando archivos nuevos al topic de Kafka: $TOPIC"

# Revisión infinita cada 10 segundos
while true; do
    # Buscar archivos .json en el directorio
    for json_file in "$WATCH_DIR"/*.json; do
        # Verifica si el archivo ya fue procesado
        if ! grep -Fxq "$json_file" "$PROCESSED_LOG"; then
            echo "🚀 Enviando $json_file a Kafka..."
            cat "$json_file" | "$KAFKA_BIN_DIR/kafka-console-producer.sh" \
                --broker-list localhost:9092 \
                --topic "$TOPIC"
            # Marcar como procesado
            echo "$json_file" >> "$PROCESSED_LOG"
            echo "✅ Archivo enviado: $json_file"
        fi
    done
    sleep 10  # Espera 10 segundos antes de revisar de nuevo
done

