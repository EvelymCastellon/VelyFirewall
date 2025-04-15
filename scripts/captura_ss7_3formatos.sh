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
    tshark -r "$PCAP_FILE" -Y "mtp3 || sccp || tcap || map" -T json > "$JSON_FILE" 2>/dev/null
    
    # CSV personalizado con campos extendidos
    tshark -r "$PCAP_FILE" -Y "mtp3 || sccp || tcap || map" -T fields \
        -e frame.time              `# Marca de tiempo` \
        -e mtp3.opc                `# Punto de código origen (MTP3)` \
        -e mtp3.dpc                `# Punto de código destino (MTP3)` \
        -e mtp3.sls                `# Selección de enlace (MTP3 SLS)` \
        -e sccp.message_type       `# Tipo de mensaje SCCP (UDT, XUDT, etc.)` \
        -e sccp.calling_party      `# Dirección de origen (SCCP)` \
        -e sccp.called_party       `# Dirección de destino (SCCP)` \
        -e tcap.session_id         `# ID de sesión (TCAP)` \
        -e tcap.opcode             `# Código de operación (TCAP)` \
        -e tcap.component_type     `# Tipo de componente (Invoke, ReturnResult)` \
        -e map.opcode              `# Operación MAP (ej: updateLocation)` \
        -e map.imsi                `# IMSI del suscriptor` \
        -e map.msisdn              `# Número MSISDN` \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    echo "Capturas guardadas en:"
    echo " - PCAP: $PCAP_FILE"
    echo " - JSON: $JSON_FILE"
    echo " - CSV:  $CSV_FILE"
    exit 0
}

trap cleanup INT

# Captura tráfico SS7 (puertos SCTP comunes en SS7/M3UA)
echo "Iniciando captura SS7 en $INTERFAZ (presiona Ctrl+C para detener)..."
tshark -i "$INTERFAZ" -f "sctp port 2905 || sctp port 9090" -w "$PCAP_FILE"
