#!/bin/bash

# Interfaz de red (definida por el usuario)
INTERFAZ="eno2"

# Nombre base del archivo (sin extensión)
BASE_NAME="ss7_traffic_$(date +%Y%m%d_%H%M%S)"

# Archivos de salida
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Función para limpiar y finalizar al recibir Ctrl+C
cleanup() {
    echo -e "\nConvirtiendo PCAP a JSON y CSV..."
    
    # JSON con todos los detalles SS7
    tshark -r "$PCAP_FILE" -Y "sctp || mtp3 || sccp || tcap || gsm_map" -T json > "$JSON_FILE" 2>/dev/null
    
    # CSV personalizado con campos extendidos
    tshark -r "$PCAP_FILE" -Y "sctp || mtp3 || sccp || tcap || gsm_map" -T fields \
        -e frame.time \
        -e mtp3.opc \
        -e mtp3.dpc \
        -e mtp3.sls \
        -e sccp.message_type \
        -e sccp.calling_party \
        -e sccp.called_party \
        -e tcap.session_id \
        -e tcap.opcode \
        -e tcap.component_type \
        -e gsm_map.opcode \
        -e gsm_map.imsi \
        -e gsm_map.msisdn \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Capturas guardadas en:"
    echo " - PCAP: $PCAP_FILE"
    echo " - JSON: $JSON_FILE"
    echo " - CSV:  $CSV_FILE"
    exit 0
}

trap cleanup INT

# Captura tráfico SS7 con filtro correcto
echo "Iniciando captura SS7 en $INTERFAZ (presiona Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "sctp" -w "$PCAP_FILE"
