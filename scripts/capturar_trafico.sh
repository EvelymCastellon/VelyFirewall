#!/bin/bash

# Preguntar al usuario el tipo de tráfico
while true; do
    echo "¿Qué tipo de tráfico deseas capturar?"
    select PROTOCOLO in "Diameter" "SS7" "Salir"; do
        case $PROTOCOLO in
            Diameter|SS7)
                break 2  # salir del select y del while
                ;;
            Salir)
                echo "Saliendo del script."
                exit 0
                ;;
            *)
                echo "Opción inválida. Intenta de nuevo."
                ;;
        esac
    done
done

# Preguntar duración de la captura
read -p "¿Cuántos segundos deseas capturar? " DURACION
if ! [[ "$DURACION" =~ ^[0-9]+$ ]]; then
    echo "Duración no válida. Usa solo números."
    exit 1
fi

# Interfaz de red
INTERFAZ="eno2"

# Archivos
BASE_NAME="${PROTOCOLO,,}_traffic_$(date +%Y%m%d_%H%M%S)"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"

# Captura y conversión automática
echo "Capturando tráfico $PROTOCOLO en $INTERFAZ por $DURACION segundos..."
if [[ "$PROTOCOLO" == "Diameter" ]]; then
    timeout "$DURACION" tshark -i "$INTERFAZ" -f "tcp port 3868 or sctp port 3868" -w "$PCAP_FILE"
else
    timeout "$DURACION" tshark -i "$INTERFAZ" -f "sctp" -w "$PCAP_FILE"
fi

echo "Convirtiendo PCAP a JSON..."
if [[ "$PROTOCOLO" == "Diameter" ]]; then
    tshark -r "$PCAP_FILE" -Y "diameter" -T json > "$JSON_FILE" 2>/dev/null
else
    tshark -r "$PCAP_FILE" -Y "sctp || mtp3 || sccp || tcap || gsm_map" -T json > "$JSON_FILE" 2>/dev/null
fi

echo "Capturas guardadas en:"
echo " - PCAP: $PCAP_FILE"
echo " - JSON: $JSON_FILE"
