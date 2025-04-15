#!/bin/bash

# Configuración
INTERFAZ="eno2"
BASE_NAME="malicious_ss7_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Filtros avanzados para SS7
MALICIOUS_FILTER="((sccp || tcap || map) && (
    sccp.message_type == 0x09 |                                            # XUDT (exploits de reruteo)
    map.opcode in {51 52} |                                                # SendRoutingInfoForSM/ProvideSubscriberInfo (tracking)
    tcap.component_type == 1 && !tcap.end |                                # Invocaciones no finalizadas (DoS)
    mtp3.opc == 0 |                                                       # Origen no autenticado
    frame.time_delta < 0.2 && sccp.msg_type == 1 |                        # Flooding
    tcap.session_id matches \"\\b(duplicate|replay)\\b\"                  # Replay de transacciones
))"

cleanup() {
    echo -e "\nProcesando capturas..."
    
    # Convertir a JSON
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T json > "$JSON_FILE" 2>/dev/null
    
    # CSV para análisis forense
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
        -e sccp.msg_type \
        -e tcap.component_type \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Amenazas SS7 detectadas:"
    echo " - Tracking, DoS, Spoofing, Replay, Falta de autenticación"
    echo "Archivos guardados en: $BASE_NAME.*"
    exit 0
}

trap cleanup INT

echo "Capturando tráfico SS7 malicioso en $INTERFAZ (Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "sctp port 2905" -w "$PCAP_FILE"
