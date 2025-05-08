#!/bin/bash

# --- Configuración ---
LOGS_DIR="/home/evelym/Lab/VelyFirewall/logs"
INTERFAZ="eno2"

# --- Validar parámetro ---
if [ -z "$1" ]; then
    echo "Error: Especifica el protocolo (Diameter/SS7)"
    exit 1
fi

PROTOCOLO=$1
mkdir -p "$LOGS_DIR"
cd "$LOGS_DIR" || exit 1

# --- Capturar duración ---
read -p "¿Cuántos segundos deseas capturar? " DURACION
if ! [[ "$DURACION" =~ ^[0-9]+$ ]]; then
    echo "Duración no válida. Usa solo números."
    exit 1
fi

# --- Generar nombres de archivo ---
BASE_NAME="${PROTOCOLO,,}_traffic_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"

# --- Ejecutar captura ---
echo "Capturando tráfico $PROTOCOLO..."
if [[ "$PROTOCOLO" == "Diameter" ]]; then
    timeout "$DURACION" tshark -i "$INTERFAZ" -f "tcp port 3868 or sctp port 3868" -w "$PCAP_FILE"
else
    timeout "$DURACION" tshark -i "$INTERFAZ" -f "sctp" -w "$PCAP_FILE"
fi

# --- Ajustar permisos ---
chmod 644 "$PCAP_FILE"
echo "PCAP guardado en: $LOGS_DIR/$PCAP_FILE"
