#!/bin/bash

# Configuración
INTERFAZ="eno2"
BASE_NAME="malicious_ss7_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Filtros para tráfico SS7 malicioso (ej: location tracking, SMS spoofing)
MALICIOUS_FILTER="(map.opcode == 51 || sccp.message_type == 0x09 || tcap.component_type == 1) && (map.imsi || map.msisdn)"

cleanup() {
    echo -e "\nProcesando capturas..."
    
    # Convertir a JSON
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T json > "$JSON_FILE" 2>/dev/null
    
    # Convertir a CSV (campos para análisis forense)
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T fields \
        -e frame.time \
        -e mtp3.opc \
        -e mtp3.dpc \
        -e sccp.calling_party \
        -e sccp.called_party \
        -e map.opcode \
        -e map.imsi \
        -e map.msisdn \
        -e tcap.session_id \
        -e tcap.opcode \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Capturas maliciosas SS7 guardadas en:"
    echo " - PCAP: $PCAP_FILE"
    echo " - JSON: $JSON_FILE"
    echo " - CSV:  $CSV_FILE"
    exit 0
}

trap cleanup INT

echo "Capturando tráfico SS7 malicioso en $INTERFAZ (Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "sctp port 2905" -w "$PCAP_FILE"

