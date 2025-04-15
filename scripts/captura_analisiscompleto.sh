#!/bin/bash

# Configuración avanzada
INTERFAZ="eno2"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Selección de protocolo
echo -e "\n\033[1;36m[+] Selecciona el protocolo:\033[0m"
PS3="Introduce el número (1-2): "
options=("SS7" "Diameter")
select opt in "${options[@]}"
do
    case $opt in
        "SS7")
            PROTOCOLO="ss7"
            PUERTO="sctp port 2905"
            break
            ;;
        "Diameter")
            PROTOCOLO="diameter"
            PUERTO="tcp port 3868 or sctp port 3868"
            break
            ;;
        *) echo "Opción inválida";;
    esac
done

# Selección de tipo de tráfico
echo -e "\n\033[1;36m[+] Tipo de tráfico:\033[0m"
PS3="Introduce el número (1-2): "
options=("Normal" "Anómalo")
select opt in "${options[@]}"
do
    case $opt in
        "Normal")
            TIPO="normal"
            break
            ;;
        "Anómalo")
            TIPO="anomalo"
            break
            ;;
        *) echo "Opción inválida";;
    esac
done

# Configuración de archivos
BASE_NAME="${PROTOCOLO}_${TIPO}_${TIMESTAMP}"
PCAP_FILE="${BASE_NAME}.pcap"
JSON_FILE="${BASE_NAME}.json"
CSV_FILE="${BASE_NAME}.csv"

# Filtros para tráfico anómalo
declare -A FILTROS_ANOMALOS=(
    ["ss7"]="(mtp3.opc == 0 || sccp.message_type == 0x09 || map.opcode in {51,52} || tcap.session_id matches \"replay\")"
    ["diameter"]="(diameter.Result-Code >= 3000 || diameter.cmd.code in {8388621,8388622} || diameter.Session_Id matches \"replay\")"
)

# Función de conversión y análisis
procesar_captura() {
    echo -e "\n\033[1;34m[+] Procesando captura...\033[0m"
    
    FILTRO=""
    if [[ "$TIPO" == "anomalo" ]]; then
        FILTRO="${FILTROS_ANOMALOS[$PROTOCOLO]}"
    else
        FILTRO="${PROTOCOLO}"
    fi

    # Conversión a JSON
    tshark -r "$PCAP_FILE" -Y "$FILTRO" -T json > "$JSON_FILE" 2>/dev/null
    
    # Campos específicos para cada protocolo
    case $PROTOCOLO in
        "ss7")
            CAMPOS=(-e mtp3.opc -e mtp3.dpc -e sccp.calling_party -e sccp.called_party 
                   -e tcap.opcode -e map.opcode -e map.imsi -e map.msisdn)
            ;;
        "diameter")
            CAMPOS=(-e diameter.Origin_Host -e diameter.Destination_Host -e diameter.cmd.code 
                   -e diameter.Result_Code -e diameter.Session_Id -e diameter.User_Name)
            ;;
    esac

    # Generación de CSV
    tshark -r "$PCAP_FILE" -Y "$FILTRO" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        "${CAMPOS[@]}" \
        -E header=y -E separator=, > "$CSV_FILE" 2>/dev/null

    # Análisis básico de seguridad
    if [[ "$TIPO" == "anomalo" ]]; then
        echo -e "\n\033[1;31m[+] Eventos sospechosos detectados:\033[0m"
        case $PROTOCOLO in
            "ss7")
                tshark -r "$PCAP_FILE" -Y "map.opcode == 51" -T pdml | grep "SendRoutingInfoForSM" 
                ;;
            "diameter")
                tshark -r "$PCAP_FILE" -Y "diameter.Result-Code >= 3000" -T pdml 
                ;;
        esac
    fi

    echo -e "\n\033[1;32m[+] Captura completada:\033[0m"
    echo "PCAP: $PCAP_FILE"
    echo "JSON: $JSON_FILE"
    echo "CSV:  $CSV_FILE"
}

# Capturar Ctrl+C
trap procesar_captura INT

# Iniciar captura
echo -e "\n\033[1;36m[+] Iniciando captura de $PROTOCOLO ($TIPO) en $INTERFAZ...\033[0m"
echo -e "\033[1;33mPresiona Ctrl+C para detener la captura\033[0m\n"

tshark -i "$INTERFAZ" -f "$PUERTO" -w "$PCAP_FILE"

# Si no se usó Ctrl+C
if [[ -f "$PCAP_FILE" ]]; then
    procesar_captura
fi
