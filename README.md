Autora
Evelym Castellón Cruz
Universidad Tecnológica de La Habana
Firewall de señalizacion para los protocolos SS7 y Diameter 
VelyFirewall: Firewall de Señalización para SS7 y Diameter

VelyFirewall es un sistema modular diseñado para detectar amenazas en redes de señalización SS7 y Diameter, combinando captura de tráfico en tiempo real con tshark, análisis dinámico mediante reglas en Python y Redis, y envío de datos a través de Kafka. El firewall permite identificar patrones como flooding SRI, IMSI catching y spoofing, utilizando contadores por IMSI almacenados en Redis. Los datos capturados se publican en el topic raw_logs y las alertas generadas se envían a alerts, donde un modelo de machine learning puede evaluar el riesgo y activar respuestas automáticas como bloqueo con iptables. Toda la infraestructura se despliega en Docker, con Kafka, Zookeeper y Redis orquestados mediante docker-compose.

Clonar el Proyecto
git clone https://github.com/EvelymCastellon/VelyFirewall.git
cd VelyFirewall

Estructura recomendada
VelyFirewall/
├── infra/             # Infraestructura: Docker Compose (Kafka, Redis, Zookeeper)
├── scripts/           # Scripts para captura, envío a Kafka y motor de reglas
├── logs/              # Carpeta donde se almacenan los logs capturados
├── models/            # Modelos de IA para detección de anomalías
├── data/              # Datos de entrenamiento / prueba
├── notebooks/         # Análisis exploratorio en Jupyter
├── api/               # Interfaz Flask o REST API (opcional)
└── docs/              # Documentación y referencias

Requisitos del sistema
Ubuntu 22.04 o superior (recomendado)

Herramientas necesarias
Herramienta	Uso principal
tshark	Captura y análisis de tráfico SS7/Diameter
scapy	Simulación de tráfico/ataques SS7 y Diameter
Docker	Infraestructura con Kafka, Redis y Zookeeper
Docker Compose	Orquestación de contenedores
Python 3.8+	Scripts de análisis y reglas dinámicas
Redis	Cache de IMSI y patrones
Kafka	Ingesta de tráfico capturado y alertas
pip, venv	Manejo de dependencias en Python
jq	Visualización y etiquetado de JSON

Pasos iniciales:
1.Crear entorno virtual de Python
python3 -m venv vely-envsource vely-env/bin/activate
pip install -r requirements.txt
2.Levantar infraestructura
cd infra
docker-compose up -d
Esto desplegará Kafka (9092), Zookeeper (2181) y Redis (6379).
Crear topics de Kafka
docker exec infra-kafka-1 kafka-topics --create --topic raw_logs --bootstrap-server localhost:9092
docker exec infra-kafka-1 kafka-topics --create --topic alerts --bootstrap-server localhost:9092
Ejecutar capturas
Desde scripts/, puedes usar:
sudo ./activar_captura.sh
Esto capturará tráfico SS7 o Diameter y lo guardará en .pcap, esos pcap serán convertidos a csv y guardados en almacenamiento, se enviaran mediante Kafka, se generarán alertas si hay algún problema y los logs serán analizados con un modelo entrenado con Machine Learning que detectará anomalías en la red y bloqueara o permitirá el trafico.
