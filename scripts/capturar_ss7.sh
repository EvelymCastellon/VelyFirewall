#!/bin/bash

# Interfaz de red
INTERFAZ="eno2"

# Nombre del archivo de salida con fecha
SALIDA="ss7_traffic_$(date +%Y%m%d_%H%M%S).pcap"

# Captura tráfico relacionado con SS7 (puertos típicos: M3UA usa SCTP 2905)
tshark -i $INTERFAZ -f "sctp port 2905" -w $SALIDA

echo "Captura de tráfico SS7 guardada en $SALIDA"
