#!/bin/bash

# Interfaz de red
INTERFAZ="eno2"

# Nombre base del archivo (sin extensión)
BASE_NAME="diameter_traffic_$(date +%Y%m%d_%H%M%S)"

# Archivos de salida
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Función para limpiar al recibir Ctrl+C
cleanup() {
    echo -e "\nConvirtiendo PCAP a JSON y CSV..."
    
    # JSON con todos los detalles
    tshark -r "$PCAP_FILE" -Y "diameter" -T json > "$JSON_FILE" 2>/dev/null
    
    # CSV personalizado (campos DIAMETER clave)
    tshark -r "$PCAP_FILE" -Y "diameter" -T fields \
        -e frame.time              `# Marca de tiempo` \
        -e diameter.cmd.code       `# Código de comando (ej: 257=CER)` \
        -e diameter.flags          `# Flags (Request/Response)` \
        -e diameter.Origin_Host    `# Origen` \
        -e diameter.Origin_Realm   `# Realm origen` \
        -e diameter.Destination_Host `# Destino` \
        -e diameter.Destination_Realm `# Realm destino` \
        -e diameter.Session_Id     `# ID de sesión` \
        -e diameter.User_Name      `# Usuario (si aplica)` \
        -e diameter.Result_Code    `# Código de resultado` \
        -e diameter.Auth_Application_Id `# ID de aplicación` \
        -e diameter.CC_Request_Type `# Tipo de solicitud (CC)` \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Capturas guardadas en:"
    echo " - PCAP: $PCAP_FILE"
    echo " - JSON: $JSON_FILE"
    echo " - CSV:  $CSV_FILE"
    exit 0
}

trap cleanup INT

# Captura inicial en PCAP
echo "Iniciando captura en $PCAP_FILE (presiona Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "tcp port 3868 or sctp port 3868" -w "$PCAP_FILE"
