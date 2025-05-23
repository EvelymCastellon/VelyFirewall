# alert_processor.py - Versión mejorada para analizar todas las filas del CSV
import requests
import pandas as pd
import json
from typing import Dict, Any, List
import time

API_URL = "http://localhost:8000"

def analizar_ss7():
    """Analiza todas las filas del último archivo CSV de tráfico SS7"""
    print("\n🔍 Evaluando riesgo de tráfico SS7...")
    try:
        # Obtener predicciones para todas las filas
        response = requests.get(f"{API_URL}/predict")
        response.raise_for_status()
        data = response.json()
        
        if "resultados" not in data:
            print("❌ Respuesta inesperada de la API")
            return
            
        resultados: List[Dict[str, Any]] = data["resultados"]
        if not resultados:
            print("⚠️ No se encontraron resultados para analizar")
            return
            
        # Mostrar información general del archivo
        fuente_log = resultados[0].get("fuente_log", "desconocido")
        print(f"\n📊 Archivo analizado: {fuente_log}")
        print(f"📝 Total de registros procesados: {len(resultados)}")
        print("="*50)
        
        # Procesar cada resultado individualmente
        for idx, resultado in enumerate(resultados, 1):
            riesgo = resultado.get("riesgo", 0)
            ip_detectada = resultado.get("ip_origen", "N/A")
            accion = resultado.get("accion", "monitorear")
            
            print(f"\n🔎 Análisis #{idx}")
            print(f"📡 IP de origen: {ip_detectada}")
            print(f"📈 Nivel de riesgo: {riesgo:.2f}%")
            
            # Tomar acción según el nivel de riesgo
            if accion == "bloquear":
                print("\n🚨🚨 ALERTA CRÍTICA 🚨🚨 (Riesgo > 90%)")
                print("🛡️ Activando protocolo de bloqueo...")
                bloquear_ip(ip_detectada)
            elif accion == "notificar":
                print("\n⚠️ ALERTA MODERADA (50% ≤ Riesgo ≤ 90%)")
                print("📢 Generando notificación de seguridad...")
                # Aquí iría el código para enviar notificaciones
                print(f"📨 Notificación enviada sobre IP {ip_detectada}")
            else:
                print("\n✅ RIESGO ACEPTABLE (Riesgo < 50%)")
                print(f"📝 Registrando tráfico normal de {ip_detectada}")
            
            print("-"*50)
            time.sleep(1)  # Pequeña pausa entre análisis

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error de conexión con la API: {str(e)}")
    except json.JSONDecodeError:
        print("\n❌ Error al decodificar la respuesta de la API")
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")

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

def analizar_sip():
    """Analiza tráfico SIP desde archivo CSV"""
    ruta_csv = "/home/evelym/Lab/VelyFirewall/infra/data/salida_sip.csv"
    print(f"\n📄 Analizando archivo SIP: {ruta_csv}")
    
    try:
        df = pd.read_csv(ruta_csv)
        
        if "label" not in df.columns or "src_ip" not in df.columns:
            print("❌ Error: El CSV debe contener columnas 'label' y 'src_ip'")
            return

        anomalias = df[df["label"] == 1]
        
        if anomalias.empty:
            print("✅ Todo el tráfico SIP es normal")
        else:
            print(f"\n🚨 Detectadas {len(anomalias)} anomalías:")
            for idx, (_, fila) in enumerate(anomalias.iterrows(), 1):
                ip = fila["src_ip"]
                print(f"\n🔎 Anomalía #{idx}")
                print(f"• IP sospechosa: {ip}")
                bloquear_ip(ip)
                print("-"*40)
                time.sleep(1)
                
    except FileNotFoundError:
        print(f"❌ Archivo no encontrado: {ruta_csv}")
    except pd.errors.EmptyDataError:
        print("❌ El archivo CSV está vacío")
    except Exception as e:
        print(f"❌ Error al analizar SIP: {str(e)}")

def menu():
    """Muestra el menú principal de interacción"""
    while True:
        print("\n" + "="*50)
        print("🔥 Firewall Inteligente - Monitor de Tráfico 🔥")
        print("="*50)
        print("1) Analizar tráfico SS7 o Diameter")
        print("2) Analizar tráfico SIP")
        print("3) Salir")
        
        opcion = input("\nSeleccione una opción (1-3): ").strip()
        
        if opcion == "1":
            analizar_ss7()
        elif opcion == "2":
            analizar_sip()
        elif opcion == "3":
            print("\n👋 Sesión finalizada\n")
            break
        else:
            print("\n❌ Opción inválida. Intente nuevamente.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n🛑 Aplicación interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {str(e)}")
