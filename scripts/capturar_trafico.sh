#!/bin/bash

# --- Configuración ---
LOGS_DIR="/home/evelym/Lab/VelyFirewall/logs"
INTERFAZ="eno2"

# --- Validar parámetro duración ---
if [ -z "$1" ]; then
    echo "Error: Debes especificar la duración de la captura (en segundos)."
    exit 1
fi

DURACION=$1
if ! [[ "$DURACION" =~ ^[0-9]+$ ]]; then
    echo "Duración no válida. Usa solo números."
    exit 1
fi

mkdir -p "$LOGS_DIR"
cd "$LOGS_DIR" || exit 1

# --- Generar nombre del archivo ---
BASE_NAME="ss7_traffic_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"

# --- Ejecutar captura solo para SS7 (SCTP) ---
echo "Capturando tráfico SS7 durante $DURACION segundos..."
timeout "$DURACION" tshark -i "$INTERFAZ" -f "sctp" -w "$PCAP_FILE"

# --- Ajustar permisos ---
chmod 644 "$PCAP_FILE"
echo "✅ PCAP guardado en: $LOGS_DIR/$PCAP_FILE"

