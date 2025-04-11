#!/bin/bash

# Selecciona la interfaz
INTERFAZ="eno2"

# Protocolo: SS7 (puerto 2905) o Diameter (puerto 3868)
echo "¿Qué protocolo deseas capturar? [ss7/diameter]"
read protocolo

if [[ "$protocolo" == "ss7" ]]; then
  FILTRO="sctp port 2905"
  ARCHIVO="ss7_trafico_etiquetado.json"
elif [[ "$protocolo" == "diameter" ]]; then
  FILTRO="tcp port 3868 or sctp port 3868"
  ARCHIVO="diameter_trafico_etiquetado.json"
else
  echo "Protocolo no válido. Usa ss7 o diameter."
  exit 1
fi

# Preguntar tipo de tráfico: normal o anómalo
echo "¿Este tráfico es normal o anómalo? [normal/anomalo]"
read etiqueta

if [[ "$etiqueta" != "normal" && "$etiqueta" != "anomalo" ]]; then
  echo "Etiqueta no válida. Usa normal o anomalo."
  exit 1
fi

echo "Capturando tráfico en formato JSON enriquecido..."
echo "Presiona Ctrl + C para detener."

# Capturar tráfico con tshark y añadir etiqueta
tshark -i "$INTERFAZ" -f "$FILTRO" -T ek -l | jq --arg etiqueta "$etiqueta" '. + {anomaly_label: $etiqueta}' > "$ARCHIVO"
