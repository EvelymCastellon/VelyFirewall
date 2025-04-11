#!/bin/bash

# Interfaz de red
INTERFAZ="eno2"

# Nombre del archivo de salida
SALIDA="diameter_traffic_$(date +%Y%m%d_%H%M%S).pcap"

# Captura tráfico Diameter (normalmente sobre TCP o SCTP, puerto 3868)
tshark -i $INTERFAZ -f "tcp port 3868 or sctp port 3868" -w $SALIDA

echo "Captura de tráfico Diameter guardada en $SALIDA"
