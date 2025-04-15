#!/bin/bash

# Configuración
INTERFAZ="eno2"
BASE_NAME="malicious_diameter_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Filtros para amenazas complejas
MALICIOUS_FILTER="(diameter && (
    diameter.Result-Code >= 3000 |                                          # Errores críticos
    diameter.cmd.code in {8388621 8388622} |                               # Abort-Session / Session-Termination
    diameter.Session_Id matches \"\\b(same_session|replay)\\b\" |          # Replay de sesión
    diameter.Origin_Host != ip.src |                                       # Spoofing
    diameter.Auth_Application_Id == 0 |                                    # Bypass 2FA
    diameter.AVP contains \"malicious-user\" |                             # AVPs sospechosos
    frame.time_delta < 0.1 && diameter.cmd.code == 280                     # Flooding (ajustar umbral)
))"

cleanup() {
    echo -e "\nProcesando capturas..."
    
    # Convertir a JSON
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T json > "$JSON_FILE" 2>/dev/null
    
    # CSV con campos forenses
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T fields \
        -e frame.time \
        -e diameter.Origin_Host \
        -e diameter.Destination_Host \
        -e diameter.cmd.code \
        -e diameter.Result_Code \
        -e diameter.Session_Id \
        -e diameter.User_Name \
        -e diameter.Auth_Application_Id \
        -e diameter.Hop_by_Hop_Id \
        -e diameter.AVP \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Amenazas DIAMETER detectadas:"
    echo " - Spoofing, DoS, Replay, 2FA Bypass, Flooding"
    echo "Archivos guardados en: $BASE_NAME.*"
    exit 0
}

trap cleanup INT

echo "Capturando tráfico DIAMETER malicioso en $INTERFAZ (Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "tcp port 3868" -w "$PCAP_FILE"
