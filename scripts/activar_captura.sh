#!/bin/bash

# --- Configuración ---
INFRA_DIR="/home/evelym/Lab/VelyFirewall/infra"
LOGS_DIR="/home/evelym/Lab/VelyFirewall/logs"
SCRIPTS_DIR="/home/evelym/Lab/VelyFirewall/scripts"
KAFKA_CONTAINER="infra-kafka-1"
KAFKA_TOPIC="raw_logs"
INTERFAZ="eno2" # Interfaz de red
PCAP_TO_CSV_SCRIPT="pcap_to_csv.py"
CAPTURAR_TRAFICO_SCRIPT="capturar_trafico.sh"
ENVIAR_CSV_KAFKA_SCRIPT="enviar_csv_kafka1.sh"

# --- 1. Activar Docker Compose ---
echo "Iniciando Docker Compose..."
cd "$INFRA_DIR" || exit 1 # Asegurarse de que estamos en el directorio correcto
docker compose up -d
echo "Docker Compose iniciado."

# --- 2. Ejecutar script de captura de tráfico ---
echo "Ejecutando script de captura de tráfico..."
cd "$LOGS_DIR" || exit 1
"$SCRIPTS_DIR"/"$CAPTURAR_TRAFICO_SCRIPT" # Ejecuta el script de captura
# El script capturar_trafico.sh ya pregunta por el tipo de tráfico y la duración [cite: 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
echo "Captura de tráfico completada."

# --- 3. Convertir PCAP a CSV y mover el PCAP ---
echo "Convirtiendo PCAP a CSV y moviendo el archivo PCAP..."
python3 "$SCRIPTS_DIR"/"$PCAP_TO_CSV_SCRIPT"
echo "Conversión a CSV y movimiento de PCAP completado."

# --- 4. Enviar CSV a Kafka ---
echo "Enviando CSV a Kafka..."
"$SCRIPTS_DIR"/"$ENVIAR_CSV_KAFKA_SCRIPT"
echo "Envío a Kafka iniciado (el script se ejecuta en bucle)."

echo "Proceso de firewall automatizado completado. El script de envío a Kafka se está ejecutando en segundo plano."
