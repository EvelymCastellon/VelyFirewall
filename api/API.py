# Comando: 
# uvicorn api:app --reload --host 0.0.0.0 --port 8000

# api.py (Adaptado para Tesis - Ray)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field # Importar Field para validación extra si es necesario
import joblib
import pandas as pd
import subprocess   # Para ejecutar iptables
import logging
import os # Para construir rutas de forma robusta

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FirewallInteligenteAPI")

# --- Carga del Modelo Entrenado ---
# Construir la ruta al modelo relativo al script api.py
# Asume que api.py está en /api y models/ está al mismo nivel que /api
# O ajusta según tu estructura final.
# Ejemplo: Si api.py está DENTRO de /api, y models/ está FUERA (en la raíz)
# MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models') # Ir un nivel arriba
MODEL_DIR = 'models' # Asume que 'models' está accesible desde donde se ejecuta la API
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')

try:
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Archivo del modelo no encontrado en la ruta esperada: {MODEL_PATH}")
        # Podrías lanzar una excepción aquí o manejarlo como prefieras
        raise FileNotFoundError(f"Modelo no encontrado en {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    logger.info(f"Modelo cargado correctamente desde: {MODEL_PATH}")
    # Intentar obtener las features esperadas por el modelo (si es posible)
    # Nota: Esto depende del tipo de modelo y si tiene el atributo feature_names_in_
    expected_features = []
    if hasattr(model, 'feature_names_in_'):
        expected_features = model.feature_names_in_
        logger.info(f"Modelo espera las siguientes features: {expected_features}")
    else:
        logger.warning("No se pudieron obtener automáticamente las features esperadas del modelo. Asegúrate que LogInput coincida.")

except FileNotFoundError as fnf_err:
    logger.critical(f"CRITICAL: {fnf_err}")
    # Salir o manejar el error de forma que la API no inicie sin modelo
    raise SystemExit(f"Fallo al cargar el modelo: {fnf_err}")
except Exception as e:
    logger.critical(f"Error CRÍTICO cargando el modelo desde {MODEL_PATH}: {e}", exc_info=True)
    # Salir o manejar el error
    raise SystemExit(f"Fallo al cargar el modelo: {e}")

# --- Definición del Esquema de Entrada (Pydantic) ---
# IMPORTANTE: Ajusta estos campos para que coincidan EXACTAMENTE
# con las columnas f_* usadas en tu script train.py
# Los nombres deben ser idénticos a las columnas del DataFrame que espera model.predict_proba()
class LogInput(BaseModel):
    # Ejemplo - reemplaza con tus features reales prefijadas con f_
    f_imsi: str = Field(..., description="IMSI del subscriptor") # Ejemplo de IMSI como feature si lo usaste
    f_protocolo_tipo: str = Field(..., description="Protocolo (ej: SS7, Diameter)") # Ejemplo
    f_operaciones_count: int = Field(..., description="Conteo de operaciones en ventana") # Ejemplo
    f_error_code_type: int = Field(..., description="Tipo de código de error") # Ejemplo
    # ... Añade aquí TODAS las demás features f_* que tu modelo necesita
    # Ejemplo: f_feature_5: float
    #          f_feature_6: int

    class Config:
        # Ejemplo para mostrar en la documentación de la API (Swagger UI)
        schema_extra = {
            "example": {
                "f_imsi": "123456789012345",
                "f_protocolo_tipo": "SS7",
                "f_operaciones_count": 15,
                "f_error_code_type": 0
                # ... añade ejemplos para tus otras features
            }
        }

# --- Definición del Esquema de Entrada para Bloqueo ---
class BlockRequest(BaseModel):
    ip: str = Field(..., description="Dirección IP a bloquear vía iptables")

# --- Inicialización de la API FastAPI ---
app = FastAPI(
    title="Firewall Inteligente API (Tesis Ray)",
    description="API para predecir riesgo en logs SS7/Diameter y ejecutar bloqueos de IP.",
    version="1.1" # Versión adaptada
)

# --- Endpoint de Predicción (/predict) ---
@app.post("/predict",
        summary="Predice el riesgo de un log SS7/Diameter",
        response_description="Devuelve el nivel de riesgo y la acción sugerida (monitorear, notificar, bloquear)")
async def predict(log: LogInput):
    """
    Recibe un log (en formato JSON con features f_*) correspondiente a tráfico
    SS7 o Diameter. Utiliza el modelo de IA entrenado para calcular un score
    de riesgo y determinar una acción.

    - **log**: Objeto JSON con las features requeridas por el modelo.

    Retorna:
    - **riesgo**: Score de riesgo (0-100).
    - **accion**: Acción sugerida ('monitorear', 'notificar', 'bloquear').
    """
    logger.info(f"Recibida petición /predict: {log.dict()}")
    try:
        # 1. Convertir el log de Pydantic a DataFrame de Pandas
        # Asegúrate que el orden y nombres de columnas coincidan con `expected_features` si se obtuvieron
        # Si no, asegúrate que coincida con lo que usaste en train.py
        input_data = pd.DataFrame([log.dict()])

        # Opcional: Reordenar columnas si expected_features está disponible y el orden importa
        if expected_features:
            try:
                input_data = input_data[expected_features] # Reordena/selecciona las columnas esperadas
            except KeyError as ke:
                missing_cols = set(expected_features) - set(input_data.columns)
                logger.error(f"Faltan columnas en la entrada /predict que el modelo espera: {missing_cols}")
                raise HTTPException(status_code=422, detail=f"Input inválido. Faltan features: {missing_cols}")

        logger.debug(f"DataFrame para predicción:\n{input_data}")

        # 2. Realizar la predicción
        # predict_proba devuelve probabilidades para cada clase [clase_0, clase_1]
        # Asumimos que la clase 1 es la 'maliciosa' o 'anómala'
        prediction_proba = model.predict_proba(input_data)
        malicious_proba = prediction_proba[:, 1][0] # Probabilidad de ser clase 1
        risk_score = round(malicious_proba * 100, 2)   # Convertir a score 0-100

        logger.info(f"Predicción realizada. Probabilidad clase 1: {malicious_proba:.4f}, Risk Score: {risk_score}%")

        # 3. Definir la acción según el umbral
        action = "monitorear" # Default
        if risk_score > 90:
            action = "bloquear"
        elif risk_score > 50: # Si no es >90 pero sí >50
            action = "notificar"

        logger.info(f"Acción determinada para risk_score {risk_score}%: {action}")

        # 4. Devolver el resultado
        return {"riesgo": risk_score, "accion": action} #

    except HTTPException as http_exc:
        # Re-lanzar excepciones HTTP para que FastAPI las maneje
        raise http_exc
    except Exception as e:
        logger.error(f"Error inesperado en /predict: {e}", exc_info=True)
        # Devolver un error genérico 500
        raise HTTPException(status_code=500, detail=f"Error interno del servidor al procesar la predicción: {e}")

# --- Endpoint de Bloqueo (/block) ---
@app.post("/block",
        summary="Bloquea una dirección IP usando iptables",
        response_description="Confirma el estado del bloqueo")
async def block_ip(request: BlockRequest):
    """
    Recibe una dirección IP y ejecuta un comando `iptables` para bloquearla.
    Este endpoint es llamado por `alert_processor.py` tanto para bloqueos
    decididos por la IA (riesgo > 90%) como para bloqueos basados en
    alertas de Suricata para tráfico SIP (etiqueta=1).

    Requiere que el proceso que ejecuta esta API tenga permisos para ejecutar
    `iptables` (posiblemente vía `sudo` sin contraseña configurado específicamente).

    - **request**: Objeto JSON con la IP a bloquear.

    Retorna:
    - **status**: 'success' o 'error'.
    - **detail**: Mensaje de error si status='error'.
    - **ip_bloqueada**: La IP que se intentó bloquear si status='success'.
    """
    ip = request.ip
    logger.warning(f"Recibida petición /block para IP: {ip}") # Warning porque es una acción importante

    # --- IMPORTANTE: Consideraciones de Seguridad ---
    # 1. Validación de IP: Asegurarse que `ip` es una IP válida antes de pasarla a un comando shell.
    #    Una librería como `ipaddress` podría usarse aquí.
    # 2. Permisos: El usuario que corre Uvicorn/Gunicorn necesita permisos para iptables.
    #    La configuración de sudoers es una opción, pero debe hacerse con cuidado.
    # 3. Inyección de Comandos: Aunque FastAPI/Pydantic ayudan, siempre sanitizar inputs que van a comandos.

    # Comando iptables (ajusta si necesitas otra regla, ej: FORWARD, OUTPUT, o si usas `sudo`)
    # command = f"sudo iptables -A INPUT -s {ip} -j DROP" # Ejemplo con sudo
    command = f"iptables -A INPUT -s {ip} -j DROP" # Asume permisos directos o sudoers configurado
    logger.info(f"Ejecutando comando: {command}")

    try:
        # Usar subprocess.run de forma más segura
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=10) # Timeout añadido

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Código de retorno no cero, sin stderr."
            logger.error(f"Error al ejecutar iptables para IP {ip}. Return code: {result.returncode}. Stderr: {error_msg}")
            # Devolver un error 500 ya que el bloqueo falló en el servidor
            raise HTTPException(status_code=500, detail=f"Error de iptables: {error_msg}")

        logger.info(f"IP {ip} bloqueada correctamente (iptables ejecutado). Salida: {result.stdout.strip()}")
        return {"status": "success", "ip_bloqueada": ip}

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ejecutando iptables para bloquear IP {ip}")
        raise HTTPException(status_code=500, detail="Timeout ejecutando comando de bloqueo.")