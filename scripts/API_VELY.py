# velyfirewall_api.py
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

app = FastAPI(title="VelyFirewall API", version="1.0.0")
app_start_time = time.time()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_PATH = "/home/evelym/Lab/VelyFirewall/scripts/models/7ef258d0e7dd4ef68d08688c4a903728_XGB_model.joblib"
DIRECTORIO_LOGS = "/home/evelym/Lab/VelyFirewall/logs"
ARCHIVO_ANALIZADOS = "/tmp/archivos_analizados_api.txt"

try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Modelo cargado desde {MODEL_PATH}")
    if hasattr(model, 'feature_names_in_'):
        expected_features = model.feature_names_in_.tolist()
    else:
        expected_features = None
        logger.warning("No se encontraron nombres de características en el modelo")
except Exception as e:
    logger.error(f"No se pudo cargar el modelo: {str(e)}")
    raise RuntimeError(f"Error al cargar el modelo: {str(e)}")

class BlockRequest(BaseModel):
    ip: str

archivos_analizados = set()
if os.path.exists(ARCHIVO_ANALIZADOS):
    with open(ARCHIVO_ANALIZADOS, 'r') as f:
        archivos_analizados = set(line.strip() for line in f if line.strip())

def guardar_archivos_analizados():
    with open(ARCHIVO_ANALIZADOS, 'w') as f:
        for archivo in archivos_analizados:
            f.write(f"{archivo}\n")

atexit.register(guardar_archivos_analizados)

def obtener_proximo_csv_no_analizado(directorio_logs: str = DIRECTORIO_LOGS) -> str:
    archivos = [f for f in os.listdir(directorio_logs)
                if f.endswith('.csv') and f not in archivos_analizados]
    if not archivos:
        return None
    archivos.sort(key=lambda x: os.path.getmtime(os.path.join(directorio_logs, x)))
    return os.path.join(directorio_logs, archivos[0])

def ip_ya_bloqueada(ip: str) -> bool:
    result = subprocess.run(
        f"iptables -L INPUT -v -n | grep {ip}",
        shell=True, capture_output=True, text=True
    )
    return result.returncode == 0

@app.get("/predict")
async def predecir_ultimo_log():
    if (time.time() - app_start_time) < 10:
        raise HTTPException(status_code=503, detail="API initializing, please wait")

    ruta_csv = obtener_proximo_csv_no_analizado()
    if not ruta_csv:
        return {"resultados": [], "message": "No hay archivos nuevos para analizar"}

    if os.path.getsize(ruta_csv) == 0:
        time.sleep(5)
        if os.path.getsize(ruta_csv) == 0:
            archivos_analizados.add(os.path.basename(ruta_csv))
            guardar_archivos_analizados()
            return {"resultados": [], "message": "Archivo vacío después de espera"}

    df = pd.read_csv(ruta_csv)

    if df.empty:
        archivos_analizados.add(os.path.basename(ruta_csv))
        guardar_archivos_analizados()
        return {"resultados": [], "message": "Archivo vacío"}

    if 'src_ip' not in df.columns or 'label' not in df.columns:
        raise HTTPException(status_code=422, detail="El archivo CSV no contiene 'src_ip' o 'label'")

    # ✅ Filtrar solo las filas anómalas (label == 1)
    df = df[df["label"] == 1]
    if df.empty:
        archivos_analizados.add(os.path.basename(ruta_csv))
        guardar_archivos_analizados()
        return {"resultados": [], "message": "No se encontraron filas anómalas para analizar"}

    resultados = []
    for _, fila in df.iterrows():
        ip_origen = fila['src_ip']
        try:
            if expected_features:
                if not all(f in fila for f in expected_features):
                    continue
                datos_modelo = pd.DataFrame([fila[expected_features]])
            else:
                columnas_features = [col for col in fila.index if col.startswith('f_')]
                if not columnas_features:
                    continue
                datos_modelo = pd.DataFrame([fila[columnas_features]])

            proba = model.predict_proba(datos_modelo)[0][1]
            riesgo = round(float(proba) * 100, 2)
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

    archivos_analizados.add(os.path.basename(ruta_csv))
    guardar_archivos_analizados()

    if not resultados:
        return {"resultados": [], "message": "No se procesaron filas"}

    return {"resultados": resultados}

@app.post("/block")
async def bloquear_ip(request: BlockRequest):
    ip = request.ip
    if ip_ya_bloqueada(ip):
        return {"status": "info", "ip_bloqueada": ip, "message": f"La IP {ip} ya está bloqueada"}
    comando = f"iptables -A INPUT -s {ip} -j DROP"
    result = subprocess.run(comando, shell=True, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr.strip())
    return {"status": "success", "ip_bloqueada": ip, "message": f"IP {ip} bloqueada en iptables"}

@app.get("/health")
async def health_check():
    return {
        "status": "active",
        "uptime": round(time.time() - app_start_time, 2),
        "version": app.version,
        "model_loaded": os.path.exists(MODEL_PATH),
        "model_type": str(type(model).__name__),
        "archivos_analizados": len(archivos_analizados)
    }
