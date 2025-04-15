#!/bin/bash

# Configuración
INTERFAZ="eno2"
BASE_NAME="malicious_diameter_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Filtros para tráfico DIAMETER sospechoso (ajustar según amenazas conocidas)
MALICIOUS_FILTER="diameter && (diameter.Result-Code >= 3000 || diameter.cmd.code == 8388621 || diameter.AVP contains \"malicious-user\")"

cleanup() {
    echo -e "\nProcesando capturas..."
    
    # Convertir a JSON
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T json > "$JSON_FILE" 2>/dev/null
    
    # Convertir a CSV (campos clave para auditoría)
    tshark -r "$PCAP_FILE" -Y "$MALICIOUS_FILTER" -T fields \
        -e frame.time \
        -e diameter.Origin_Host \
        -e diameter.Destination_Host \
        -e diameter.cmd.code \
        -e diameter.Result_Code \
        -e diameter.Session_Id \
        -e diameter.User_Name \
        -e diameter.Auth_Application_Id \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Capturas maliciosas DIAMETER guardadas en:"
    echo " - PCAP: $PCAP_FILE"
    echo " - JSON: $JSON_FILE"
    echo " - CSV:  $CSV_FILE"
    exit 0
}

trap cleanup INT

echo "Capturando tráfico DIAMETER malicioso en $INTERFAZ (Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "tcp port 3868" -w "$PCAP_FILE"
