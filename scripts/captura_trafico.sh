#!/bin/bash

# Interfaz de red
INTERFAZ="eno2"

# Carpeta destino (puedes cambiarla si quieres)
DESTINO="./data/capturas"

# Fecha y hora para los nombres de archivo
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Asegurar que el destino existe
mkdir -p "$DESTINO"

echo "⏺️ Capturando tráfico Diameter..."
tshark -i "$INTERFAZ" \
  -Y "diameter.cmd.code == 257 || diameter.cmd.code == 316 || diameter.cmd.code == 318" \
  -T json > "$DESTINO/diameter_traffic_$TIMESTAMP.json" &

PID_DIAMETER=$!

echo "⏺️ Capturando tráfico SS7..."
tshark -i "$INTERFAZ" \
  -Y "gsm_map.sri || gsm_map.sri_sm || gsm_map.updateLocation || gsm_map.insertSubscriberData" \
  -T json > "$DESTINO/ss7_traffic_$TIMESTAMP.json" &

PID_SS7=$!

echo "✅ Capturas iniciadas. Presiona [CTRL+C] para detener."

# Esperar que las capturas terminen si no se cancela
wait $PID_DIAMETER $PID_SS7
