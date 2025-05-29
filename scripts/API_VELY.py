from fastapi import FastAPI, HTTPException
import pandas as pd
import os
import time
import subprocess
import logging
from typing import List, Dict, Any
from pydantic import BaseModel
import joblib
import numpy as np
import atexit

# Configuración básica de la aplicación
app = FastAPI(title="VelyFirewall API", version="1.0.0")
app_start_time = time.time()

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ruta al modelo entrenado
MODEL_PATH = "/home/evelym/Lab/VelyFirewall/scripts/models/7ef258d0e7dd4ef68d08688c4a903728_XGB_model.joblib"
DIRECTORIO_LOGS = "/home/evelym/Lab/VelyFirewall/logs"

# Archivo para guardar la lista de archivos analizados
ARCHIVO_ANALIZADOS = "/tmp/archivos_analizados_api.txt"

# Cargar el modelo al iniciar la API
try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Modelo cargado correctamente desde {MODEL_PATH}")
    
    # Obtener las características esperadas del modelo
    if hasattr(model, 'feature_names_in_'):
        expected_features = model.feature_names_in_.tolist()
    else:
        # Si el modelo no tiene feature_names_in_, asumir columnas f_*
        expected_features = None
        logger.warning("El modelo no tiene feature_names_in_. Se asumirán columnas con prefijo 'f_'")
    
    logger.info(f"Características esperadas por el modelo: {expected_features}")
except Exception as e:
    logger.error(f"Error cargando el modelo: {str(e)}")
    raise RuntimeError(f"No se pudo cargar el modelo: {str(e)}")

# Modelo de datos para el endpoint /block
class BlockRequest(BaseModel):
    ip: str

# Conjunto para mantener registro de archivos analizados
archivos_analizados = set()

# Cargar archivos analizados previos si existen
if os.path.exists(ARCHIVO_ANALIZADOS):
    try:
        with open(ARCHIVO_ANALIZADOS, 'r') as f:
            for linea in f:
                archivo = linea.strip()
                if archivo:  # evitar líneas vacías
                    archivos_analizados.add(archivo)
        logger.info(f"Cargados {len(archivos_analizados)} archivos analizados previamente")
    except Exception as e:
        logger.error(f"Error cargando archivos analizados: {str(e)}")

# Función para guardar la lista de analizados
def guardar_archivos_analizados():
    try:
        with open(ARCHIVO_ANALIZADOS, 'w') as f:
            for archivo in archivos_analizados:
                f.write(f"{archivo}\n")
    except Exception as e:
        logger.error(f"Error guardando archivos analizados: {str(e)}")

# Registrar función de guardado al salir
atexit.register(guardar_archivos_analizados)

# Función para obtener el próximo archivo CSV no analizado
def obtener_proximo_csv_no_analizado(directorio_logs: str = DIRECTORIO_LOGS) -> str:
    """Obtiene el próximo archivo CSV no analizado en el directorio de logs"""
    try:
        archivos = [f for f in os.listdir(directorio_logs) 
                   if f.endswith('.csv') and f not in archivos_analizados]
        
        if not archivos:
            logger.info("No se encontraron archivos CSV nuevos para analizar")
            return None
        
        # Ordenar por fecha de modificación (el más antiguo primero)
        archivos.sort(key=lambda x: os.path.getmtime(os.path.join(directorio_logs, x)))
        return os.path.join(directorio_logs, archivos[0])
        
    except Exception as e:
        logger.error(f"Error al buscar archivos CSV: {str(e)}")
        raise

# Función para verificar si una IP ya está bloqueada
def ip_ya_bloqueada(ip: str) -> bool:
    """Verifica si una IP ya está en las reglas de iptables"""
    try:
        result = subprocess.run(
            f"iptables -L INPUT -v -n | grep {ip}",
            shell=True,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error verificando IP bloqueada: {str(e)}")
        return False

# Endpoint para obtener predicciones
@app.get("/predict")
async def predecir_ultimo_log():
    """Endpoint para analizar el próximo archivo CSV de tráfico no analizado"""
    try:
        # Verificar si la API ha terminado de inicializarse
        if (time.time() - app_start_time) < 10:
            raise HTTPException(
                status_code=503,
                detail="API initializing, please wait"
            )

        # Obtener el próximo archivo no analizado
        ruta_csv = obtener_proximo_csv_no_analizado()
        if not ruta_csv:
            return {"resultados": [], "message": "No hay archivos nuevos para analizar"}
        
        logger.info(f"Procesando archivo: {ruta_csv}")
        
        # Verificar si el archivo está vacío
        if os.path.getsize(ruta_csv) == 0:
            logger.warning("Archivo CSV vacío encontrado. Reintentando en 5 segundos...")
            time.sleep(5)
            
            # Verificar nuevamente después de esperar
            if os.path.getsize(ruta_csv) == 0:
                logger.warning("Archivo CSV sigue vacío después de esperar. Pasando al siguiente.")
                # Marcar como analizado para no intentar de nuevo
                nombre_archivo = os.path.basename(ruta_csv)
                archivos_analizados.add(nombre_archivo)
                guardar_archivos_analizados()
                return {"resultados": [], "message": "Archivo vacío después de espera"}

        # Leer el archivo CSV
        df = pd.read_csv(ruta_csv)
        if df.empty:
            logger.warning("Archivo CSV vacío después de lectura")
            nombre_archivo = os.path.basename(ruta_csv)
            archivos_analizados.add(nombre_archivo)
            guardar_archivos_analizados()
            return {"resultados": [], "message": "Archivo vacío"}

        # Verificar columna src_ip (requerida)
        if 'src_ip' not in df.columns:
            logger.error("Columna 'src_ip' no encontrada en CSV")
            nombre_archivo = os.path.basename(ruta_csv)
            archivos_analizados.add(nombre_archivo)
            guardar_archivos_analizados()
            raise HTTPException(
                status_code=422,
                detail="El archivo CSV no contiene la columna 'src_ip'"
            )

        # Procesar cada fila del CSV
        resultados = []
        for _, fila in df.iterrows():
            ip_origen = fila['src_ip']
            
            # Preparar los datos para el modelo
            try:
                # Si el modelo tiene características esperadas, filtrar y ordenar
                if expected_features:
                    # Verificar que todas las características estén presentes
                    missing = set(expected_features) - set(fila.index)
                    if missing:
                        logger.error(f"Columnas faltantes: {missing}")
                        continue
                    
                    # Crear DataFrame con las características en el orden correcto
                    datos_modelo = pd.DataFrame([fila[expected_features]])
                else:
                    # Si no hay características esperadas, usar todas las columnas que empiecen con f_
                    columnas_features = [col for col in fila.index if col.startswith('f_')]
                    if not columnas_features:
                        logger.error("No se encontraron columnas de features (f_*)")
                        continue
                    datos_modelo = pd.DataFrame([fila[columnas_features]])

                # Realizar predicción con el modelo real
                proba = model.predict_proba(datos_modelo)[0][1]
                riesgo = round(float(proba) * 100, 2)
                
                # Clasificación según score
                if riesgo > 90:
                    accion = "bloquear"
                elif riesgo > 50:
                    accion = "notificar"
                else:
                    accion = "monitorear"

                resultados.append({
                    "ip_origen": ip_origen,
                    "riesgo": riesgo,
                    "accion": accion,
                    "fuente_log": os.path.basename(ruta_csv)
                })
                
            except Exception as e:
                logger.error(f"Error en predicción para IP {ip_origen}: {str(e)}")
                continue

        # Marcar el archivo como analizado
        nombre_archivo = os.path.basename(ruta_csv)
        archivos_analizados.add(nombre_archivo)
        guardar_archivos_analizados()
        
        if not resultados:
            logger.warning("No se pudo procesar ninguna fila del CSV")
            return {"resultados": [], "message": "No se procesaron filas"}

        return {"resultados": resultados}

    except FileNotFoundError as e:
        logger.error(f"Archivo no encontrado: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error durante la predicción")
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )

# Endpoint para bloquear IPs
@app.post("/block")
async def bloquear_ip(request: BlockRequest):
    """Endpoint para bloquear una IP en el firewall"""
    ip = request.ip
    
    # Verificar si ya está bloqueada
    if ip_ya_bloqueada(ip):
        logger.info(f"IP {ip} ya está bloqueada")
        return {
            "status": "info",
            "ip_bloqueada": ip,
            "message": f"La IP {ip} ya se encuentra bloqueada"
        }

    # Comando para bloquear la IP
    comando = f"iptables -A INPUT -s {ip} -j DROP"
    try:
        logger.info(f"Intentando bloquear IP: {ip}")
        result = subprocess.run(
            comando,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            logger.error(f"Error bloqueando IP: {result.stderr.strip()}")
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip()
            )
        
        logger.info(f"IP bloqueada exitosamente: {ip}")
        return {
            "status": "success",
            "ip_bloqueada": ip,
            "message": f"IP {ip} bloqueada en iptables"
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout al bloquear IP {ip}")
        raise HTTPException(
            status_code=500,
            detail="El comando iptables tardó demasiado"
        )
    except Exception as e:
        logger.error(f"Error inesperado bloqueando IP: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# Endpoint de verificación de salud
@app.get("/health")
async def health_check():
    """Endpoint para verificar el estado de la API"""
    return {
        "status": "active",
        "uptime": round(time.time() - app_start_time, 2),
        "version": app.version,
        "model_loaded": os.path.exists(MODEL_PATH),
        "model_type": str(type(model).__name__) if 'model' in globals() else "none",
        "archivos_analizados": len(archivos_analizados)
    }
