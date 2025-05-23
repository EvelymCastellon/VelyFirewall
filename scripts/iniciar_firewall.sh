
#!/bin/bash

# 1. Asegurar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
  echo "Este script debe ejecutarse como root. Usa: sudo ./iniciar_proceso.sh"
  exit 1
fi

# 2. Activar entorno virtual
cd /home/evelym/Lab || exit
source scapy-env/bin/activate

# 3. Ejecutar script de captura
cd /home/evelym/Lab/VelyFirewall/scripts || exit
./activar_captura_3protocolos_sh

# 4. Ejecutar el procesador de alertas (sin iniciar API automáticamente)
echo "🟡 Ejecutando alert_processor.py..."
echo "⚠️ ATENCIÓN: La API debe estar ejecutándose manualmente para que el procesador de alertas funcione"
python3 alert_processor.py

echo "✅ Proceso terminado"
