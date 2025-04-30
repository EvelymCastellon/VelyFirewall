#!/bin/bash

# Paso 1: Activar docker-compose
echo "🚀 Iniciando servicios de infraestructura..."
cd /home/evelym/Lab/VelyFirewall/infra || { echo "❌ No se encontró la carpeta infra"; exit 1; }
docker-compose up -d

# Paso 2: Ejecutar captura de tráfico
echo "🌐 Ejecutando módulo de captura..."
cd /home/evelym/Lab/VelyFirewall/logs || { echo "❌ No se encontró la carpeta logs"; exit 1; }
/home/evelym/Lab/VelyFirewall/scripts/capturar_trafico.sh

# Paso 3: Convertir .pcap a .csv y mover el .pcap a almacenamiento
echo "📄 Convirtiendo .pcap a .csv..."
python3 /home/evelym/Lab/VelyFirewall/scripts/pcap_to_csv.py

# Paso 4: Enviar .csv a Kafka
echo "📤 Enviando .csv a Kafka..."
bash /home/evelym/Lab/VelyFirewall/scripts/enviar_csv_kafka.sh
