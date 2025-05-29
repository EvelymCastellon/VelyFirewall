# alert_processor.py - Analiza tráfico SS7 y SIP
import requests
import pandas as pd
import time
import os
from typing import Dict, Any, List

API_URL = "http://localhost:8000"
INTERVALO_ANALISIS = 10  # segundos entre ciclos completos de análisis
RUTA_SIP_CSV = "/home/evelym/Lab/VelyFirewall/infra/data/salida_sip.csv"

def bloquear_ip(ip: str):
    """Bloquea una IP verificando primero si ya está bloqueada"""
    try:
        print(f"\n🛡️ Verificando estado de IP {ip}...")
        response = requests.post(f"{API_URL}/block", json={"ip": ip})
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "info":
                print(f"ℹ️ {data.get('message')}")
            else:
                print(f"✅ {data.get('message')}")
        else:
            print(f"⚠️ Error en el bloqueo. Código: {response.status_code}")
            print(f"📄 Respuesta: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {str(e)}")
    except Exception as e:
        print(f"❌ Error al bloquear IP: {str(e)}")

def analizar_ss7_diameter():
    """Analiza tráfico SS7"""
    try:
        print("\n" + "="*50)
        print("🔥 Firewall Inteligente - Análisis SS7 🔥")
        print("="*50)
        
        print("\n🔍 Solicitando predicciones de riesgo a la API...")
        response = requests.get(f"{API_URL}/predict")
        response.raise_for_status()
        data = response.json()
        
        # Manejar mensajes especiales de la API
        if "message" in data:
            print(f"\nℹ️ {data['message']}")
            return
            
        if "resultados" not in data:
            print("❌ Respuesta inesperada de la API")
            return
            
        resultados: List[Dict[str, Any]] = data["resultados"]
        if not resultados:
            print("⚠️ En este momento no hay tráfico SS7 por analizar")
            return
            
        # Mostrar información general
        fuente_log = resultados[0].get("fuente_log", "desconocido")
        print(f"\n📊 Archivo analizado: {fuente_log}")
        print(f"📝 Total de registros procesados: {len(resultados)}")
        print("="*50)
        
        # Procesar cada resultado
        for idx, resultado in enumerate(resultados, 1):
            riesgo = resultado.get("riesgo", 0)
            ip_detectada = resultado.get("ip_origen", "N/A")
            accion = resultado.get("accion", "monitorear")
            
            print(f"\n🔎 Análisis #{idx}")
            print(f"📡 IP de origen: {ip_detectada}")
            print(f"📈 Nivel de riesgo: {riesgo:.2f}%")
            
            # Tomar acción según riesgo
            if accion == "bloquear":
                print("\n🚨🚨 ALERTA CRÍTICA 🚨🚨 (Riesgo > 90%)")
                print("🛡️ Activando protocolo de bloqueo...")
                bloquear_ip(ip_detectada)
            elif accion == "notificar":
                print("\n⚠️ ALERTA MODERADA (50% ≤ Riesgo ≤ 90%)")
                print("📢 Generando notificación de seguridad...")
                print(f"📨 Notificación enviada sobre IP {ip_detectada}")
            else:
                print("\n✅ RIESGO ACEPTABLE (Riesgo < 50%)")
                print(f"📝 Registrando tráfico normal de {ip_detectada}")
            
            print("-"*50)
            time.sleep(0.5)

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error de conexión con la API: {str(e)}")
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")

def analizar_sip():
    """Analiza tráfico SIP"""
    print("\n" + "="*50)
    print("🔥 Firewall Inteligente - Análisis SIP 🔥")
    print("="*50)
    print(f"\n📄 Analizando archivo SIP: {RUTA_SIP_CSV}")
    
    try:
        # Verificar si el archivo existe
        if not os.path.exists(RUTA_SIP_CSV):
            print(f"❌ Archivo no encontrado: {RUTA_SIP_CSV}")
            return
            
        # Verificar si el archivo está vacío
        if os.path.getsize(RUTA_SIP_CSV) == 0:
            print("En este momento no hay tráfico SIP por analizar")
            return

        # Leer el archivo CSV
        df = pd.read_csv(RUTA_SIP_CSV)
        
        # Validar columnas requeridas
        if "label" not in df.columns or "src_ip" not in df.columns:
            print("❌ Error: El CSV debe contener columnas 'label' y 'src_ip'")
            return

        # Buscar anomalías
        anomalias = df[df["label"] == 1]
        
        if anomalias.empty:
            print("✅ No se encontró ninguna anomalía, todo el tráfico SIP es normal")
        else:
            print(f"\n🚨 Detectadas {len(anomalias)} anomalías:")
            for idx, (_, fila) in enumerate(anomalias.iterrows(), 1):
                ip = fila["src_ip"]
                print(f"\n🔎 Anomalía #{idx}")
                print(f"• IP sospechosa: {ip}")
                bloquear_ip(ip)
                print("-"*40)
                time.sleep(1)
                
    except pd.errors.EmptyDataError:
        print("⚠️ El archivo no tiene datos válidos. Omitiendo análisis SIP.")
    except Exception as e:
        print(f"❌ Error al analizar SIP: {str(e)}")

def ciclo_completo_analisis():
    """Ejecuta un ciclo completo de análisis para ambos protocolos"""
    inicio_ciclo = time.time()
    
    # 1. Analizar SS7/Diameter
    analizar_ss7_diameter()
    
    # 2. Analizar SIP
    analizar_sip()
    
    # Calcular tiempo transcurrido
    tiempo_transcurrido = time.time() - inicio_ciclo
    return tiempo_transcurrido

if __name__ == "__main__":
    print("Iniciando análisis continuo de tráfico SS7 y SIP...")
    print(f"🔁 Ciclo completo de análisis cada {INTERVALO_ANALISIS} segundos")
    print("Presione Ctrl+C para detener\n")
    
    try:
        while True:
            tiempo_analisis = ciclo_completo_analisis()
            
            # Calcular tiempo de espera restante
            tiempo_espera = max(0, INTERVALO_ANALISIS - tiempo_analisis)
            
            if tiempo_espera > 0:
                print(f"\n⏱️ Próximo ciclo de análisis en {tiempo_espera:.1f} segundos...")
                time.sleep(tiempo_espera)
            else:
                print("\n⏱️ Tiempo de análisis excedido. Iniciando nuevo ciclo inmediatamente...")
                
    except KeyboardInterrupt:
        print("\n\n🛑 Análisis interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {str(e)}")
