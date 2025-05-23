# -*- coding: utf-8 -*-
"""
train.py — Entrenamiento de modelo con Validación Cruzada y logging en MLflow.
(Versión 5.8.9 - Corregido NameError en preprocess)

Incluye RandomizedSearchCV opcional para RF/XGB/LGBM, prueba dinámica de
umbrales, opción SMOTE/balanceo intrínseco y Early Stopping corregido (también en RS).
Soporte para RandomForest, LightGBM y XGBoost (CPU/GPU configurable).
Manejo robusto de n_jobs en SMOTE y opción sampling_strategy.
Configuración MLflow mejorada y correcciones en logs de resumen.
MODIFICACIÓN: Corregido NameError en return de preprocess().
"""

import os
import sys
import logging
import traceback
import joblib
import pandas as pd
import numpy as np
import csv
from datetime import datetime
import time  # Para medir tiempos
import warnings # Importar warnings
import platform # Para chequeo de OS (SMOTE)

# Modelos y herramientas de Scikit-learn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    StratifiedKFold,
    train_test_split,
    GridSearchCV,  # Mantenido por si se quiere usar
    RandomizedSearchCV
)
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    auc,
    precision_recall_fscore_support,
    accuracy_score # Añadido para métrica simple
)
from sklearn.impute import SimpleImputer # Opción para manejo de NaNs más avanzado

# Modelos específicos y sus herramientas
try:
    import lightgbm as lgb
    from lightgbm import LGBMClassifier
    LGBM_AVAILABLE = True
except ImportError:
    LGBMClassifier = None
    lgb = None
    LGBM_AVAILABLE = False
    logging.warning("LightGBM no está instalado. Modelo LGBM no disponible.")

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBClassifier = None
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost no está instalado. Modelo XGB no disponible.")

# Herramientas adicionales
try:
    from imblearn.over_sampling import SMOTE
    IMBLEARN_AVAILABLE = True
except ImportError:
    SMOTE = None
    IMBLEARN_AVAILABLE = False
    logging.warning("imbalanced-learn no está instalado. SMOTE no disponible.")

import mlflow
import mlflow.sklearn
# <<< CAMBIO 2.b (Importar excepciones MLflow) - Aunque no estrictamente necesario si ya está importado mlflow >>>
# import mlflow.exceptions
from mlflow.models.signature import infer_signature
import configparser
import matplotlib.pyplot as plt
from typing import Optional, Dict, Any, Tuple, Union, List
import ast
from scipy.stats import randint as sp_randint
from scipy.stats import uniform as sp_uniform

# --- Configuración de rutas base ---
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # Fallback si __file__ no está definido (ej: ejecución interactiva)
    BASE_DIR = os.getcwd()

CONFIG_PATH = os.path.join(BASE_DIR, 'config.ini')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
LOG_DIR = os.path.join(BASE_DIR, 'logs')

for d in (MODEL_DIR, REPORT_DIR, LOG_DIR):
    os.makedirs(d, exist_ok=True)

# --- Logging ---
log_file = os.path.join(LOG_DIR, 'training.log')
# Asegurarse que el logger no acumule handlers de ejecuciones previas si el script se importa/re-ejecuta
logger = logging.getLogger('ThesisTraining')
if not logger.handlers: # Configurar solo si no tiene handlers
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a') # Append mode
    file_handler.setLevel(logging.INFO)
    file_fmt = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Dejar en INFO para ver el progreso
    console_fmt = logging.Formatter('%(levelname)s:%(message)s')
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# --- Funciones Auxiliares de Configuración ---

def _convert_param_type(value: str) -> Any:
    """Intenta convertir un valor string del config a int, float, bool, None o lo deja como string."""
    value = value.strip()
    if not value: return None
    lower_value = value.lower()
    if lower_value == 'none': return None
    if lower_value == 'true': return True
    if lower_value == 'false': return False
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            # Devolver como string, quitando comillas si las hay
            if (value.startswith("'") and value.endswith("'")) or \
            (value.startswith('"') and value.endswith('"')):
                return value[1:-1]
            return value

def _parse_param_dist(value: str) -> Any:
    """ Parsea una distribución de parámetros o valor fijo desde config.ini.
        Admite randint, uniform, listas, None, True, False, números y strings.
    """
    value = value.strip()
    lower_value = value.lower()
    if lower_value == 'none': return None
    if lower_value == 'true': return True
    if lower_value == 'false': return False

    # Intentar distribuciones scipy.stats
    if value.startswith('randint(') and value.endswith(')'):
        try:
            # Extraer argumentos de forma segura
            args_str = value[len('randint('):-1]
            args = ast.literal_eval(f"({args_str})") # Evaluar como tupla
            return sp_randint(*args)
        except Exception as e:
            logger.warning(f"Error parseando randint '{value}': {e}. Tratando como string.")
            return value.strip("'\"")
    if value.startswith('uniform(') and value.endswith(')'):
        try:
            args_str = value[len('uniform('):-1]
            args = ast.literal_eval(f"({args_str})")
            return sp_uniform(*args)
        except Exception as e:
            logger.warning(f"Error parseando uniform '{value}': {e}. Tratando como string.")
            return value.strip("'\"")

    # Intentar listas, tuplas, dicts
    if (value.startswith('[') and value.endswith(']')) or \
    (value.startswith('(') and value.endswith(')')) or \
    (value.startswith('{') and value.endswith('}')):
        try:
            return ast.literal_eval(value)
        except Exception as e:
            logger.warning(f"Error parseando estructura '{value}' con literal_eval: {e}. Tratando como string.")
            return value.strip("'\"")

    # Intentar números
    try: return int(value)
    except ValueError:
        try: return float(value)
        except ValueError:
            # Fallback a string, quitando comillas si las hay
            if (value.startswith("'") and value.endswith("'")) or \
                (value.startswith('"') and value.endswith('"')):
                return value[1:-1]
            return value

def load_config() -> Dict[str, Any]:
    """
    Carga configuración desde config.ini, combinando secciones y validando.
    """
    if not os.path.exists(CONFIG_PATH):
        logger.critical(f"Archivo de configuración no encontrado en {CONFIG_PATH}")
        sys.exit(1)

    config = configparser.ConfigParser(
        interpolation=None,
        allow_no_value=True,
        inline_comment_prefixes=('#', ';'),
        converters={'param_dist': _parse_param_dist, 'convert': _convert_param_type} # Usar conversores
    )
    try:
        config.read(CONFIG_PATH, encoding='utf-8')
    except Exception as e:
        logger.critical(f"Error al leer config.ini: {e}")
        sys.exit(1)

    cfg: Dict[str, Any] = {}
    try:
        # 1. Leer model_type (requerido)
        model_type = config.get('model', 'model_type', fallback=None)
        if not model_type:
            raise ValueError("La sección [model] con la opción 'model_type' es requerida en config.ini")
        model_type = model_type.lower().strip()
        cfg['model_type'] = model_type
        valid_models = ['rf', 'xgb', 'lgbm']
        if model_type == 'xgb' and not XGBOOST_AVAILABLE:
            raise ValueError("XGBoost seleccionado (xgb) pero no parece estar instalado.")
        if model_type == 'lgbm' and not LGBM_AVAILABLE:
            raise ValueError("LightGBM seleccionado (lgbm) pero no parece estar instalado.")
        if model_type not in valid_models:
            raise ValueError(f"model_type '{model_type}' no válido. Usar uno de {valid_models} (asegúrate que esté instalado).")

        # 2. Leer [common_params]
        common_params = {}
        if config.has_section('common_params'):
            # Usar el conversor 'convert' definido arriba
            common_params = {k: config.getconvert('common_params', k) for k in config.options('common_params')}
            logger.info(f"Parámetros comunes cargados: {common_params}")
        cfg.update(common_params) # Actualizar cfg base con comunes

        # 3. Leer sección específica del modelo [<model_type>_params]
        model_section_name = f"{model_type}_params"
        if config.has_section(model_section_name):
            model_specific_params = {k: config.getconvert(model_section_name, k) for k in config.options(model_section_name)}
            logger.info(f"Parámetros específicos para '{model_type}' cargados: {model_specific_params}")
            cfg.update(model_specific_params) # Sobrescribir comunes si hay colisión

        # 4. Leer distribuciones para RandomizedSearch [<model_type>_param_dist]
        param_dist_section_name = f"{model_type}_param_dist"
        if cfg.get('use_randomsearch', False): # Usar valor ya cargado de common_params
            if config.has_section(param_dist_section_name):
                # Usar el conversor 'param_dist' definido arriba
                param_dist = {k: config.getparam_dist(param_dist_section_name, k) for k in config.options(param_dist_section_name)}
                logger.info(f"Distribuciones de parámetros para RandomizedSearch ('{model_type}') cargadas: {param_dist}")
                cfg['param_dist'] = param_dist # Guardar en la config
            else:
                logger.warning(f"use_randomsearch=True pero no se encontró la sección [{param_dist_section_name}]. RandomizedSearch NO se ejecutará.")
                cfg['use_randomsearch'] = False # Desactivar si no hay distribución

        # 5. Leer parámetros de otras secciones (paths, validation, processing, mlflow, evaluation)
        other_sections = ['paths', 'validation', 'processing', 'mlflow', 'evaluation']
        for section in other_sections:
            if config.has_section(section):
                for key in config.options(section):
                    if key not in cfg: # Evitar sobrescribir lo ya cargado/combinado
                        # Usar el conversor 'convert' general
                        cfg[key] = config.getconvert(section, key)

        # --- Validaciones y Defaults Post-Carga ---
        cfg.setdefault('random_state', 42)
        cfg.setdefault('cv_folds', 5)
        # n_jobs: Default a -1 (todos los cores) si no está especificado
        cfg.setdefault('n_jobs', -1)
        cfg.setdefault('use_smote', False)
        cfg.setdefault('use_gridsearch', False)
        cfg.setdefault('use_randomsearch', False)
        cfg.setdefault('n_iter', 10)
        cfg.setdefault('classification_threshold', 0.5)
        cfg.setdefault('thresholds_to_test', '[0.3, 0.4, 0.5]') # Guardado como string
        cfg.setdefault('early_stopping_rounds', None)
        cfg.setdefault('smote_sampling_strategy', 'auto') # Default para SMOTE

        # Defaults específicos de modelo (si no están en config)
        if model_type == 'rf':
            cfg.setdefault('n_estimators', 100)
        elif model_type == 'xgb':
            cfg.setdefault('n_estimators', 100)
            cfg.setdefault('learning_rate', 0.1)
            cfg.setdefault('max_depth', 3)
            cfg.setdefault('tree_method', 'auto') # 'auto' permite que XGB decida
            # Asegurar eval_metric si ES está activado
            if cfg.get('early_stopping_rounds') is not None:
                cfg.setdefault('eval_metric', 'auc')
        elif model_type == 'lgbm':
            cfg.setdefault('n_estimators', 100)
            cfg.setdefault('learning_rate', 0.1)
            cfg.setdefault('num_leaves', 31)
            cfg.setdefault('device', 'cpu') # Default a CPU si no se especifica
            # Asegurar metric si ES está activado
            if cfg.get('early_stopping_rounds') is not None:
                cfg.setdefault('metric', 'auc')


        # Validar y loggear settings de GPU (si están configurados)
        gpu_used = False
        if model_type == 'xgb' and cfg.get('tree_method') == 'gpu_hist':
            logger.info("Configuración detectada para usar GPU con XGBoost (tree_method='gpu_hist').")
            gpu_used = True
        # <<< CAMBIO 1.b - Log explícito para GPU en LGBM >>>
        if model_type == 'lgbm' and cfg.get('device', '').lower() == 'gpu':
            # logger.info("Configuración detectada para usar GPU con LightGBM (device='gpu').") # Log original
            logger.info("LightGBM está utilizando GPU.") # Nuevo log solicitado
            gpu_used = True
        if not gpu_used and model_type in ('xgb', 'lgbm'):
            logger.info(f"Entrenamiento de {model_type.upper()} configurado para usar CPU.")

        # Loggear n_jobs final
        logger.info(f"Paralelización configurada para usar {cfg.get('n_jobs')} jobs (CPUs). (-1 = todos)")

        # Advertencias actualizadas sobre balanceo
        if cfg.get('use_smote'):
            if not IMBLEARN_AVAILABLE:
                logger.error("SMOTE configurado (use_smote=True) pero imbalanced-learn no está instalado. SMOTE no se aplicará.")
                cfg['use_smote'] = False # Desactivar para el resto del script
            else:
                logger.warning("SMOTE está activado (use_smote = True). Parámetros de balanceo del modelo (class_weight/scale_pos_weight) serán ignorados o deben ser None/1.0.")

        if cfg.get('use_randomsearch'): logger.info(f"RandomizedSearchCV está HABILITADO con n_iter={cfg.get('n_iter')}.")
        if cfg.get('early_stopping_rounds') is not None:
            logger.info(f"Early Stopping está configurado con {cfg.get('early_stopping_rounds')} rondas (aplicable a XGB/LGBM).")

        # Convertir thresholds_to_test de string a lista
        try:
            # Asegurarse que es string antes de evaluar
            thresh_str = cfg['thresholds_to_test']
            if isinstance(thresh_str, str):
                cfg['thresholds_to_test'] = ast.literal_eval(thresh_str)
            if not isinstance(cfg['thresholds_to_test'], list): raise ValueError("Debe ser una lista")
        except Exception:
            logger.warning(f"Error parseando 'thresholds_to_test'. Usando default [0.3, 0.4, 0.5]. Asegúrate que esté como una lista válida en config.ini (ej: [0.3, 0.4, 0.5])")
            cfg['thresholds_to_test'] = [0.3, 0.4, 0.5]

        logger.info(f"Configuración final combinada para '{model_type}': {cfg}")
        return cfg

    except (configparser.Error, ValueError, KeyError) as e:
        logger.critical(f"Error procesando config.ini: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Error inesperado al parsear config.ini: {e}\n{traceback.format_exc()}")
        sys.exit(1)

# --- Funciones de Procesamiento de Datos ---

def load_data(csv_path: str) -> Optional[pd.DataFrame]:
    """Carga los datos desde un archivo CSV, detectando separador."""
    if not os.path.exists(csv_path):
        logger.error(f"Archivo CSV no encontrado en: {csv_path}")
        return None
    try:
        sep = ',' # Default separator
        try:
            sniffer = csv.Sniffer()
            with open(csv_path, 'r', encoding='utf-8') as f_sniffer:
                sample_size_sniffer = 0
                if os.path.exists(csv_path): sample_size_sniffer = os.path.getsize(csv_path)
                # Leer un fragmento más pequeño para evitar problemas de memoria con archivos grandes
                sample = f_sniffer.read(min(1024 * 5, sample_size_sniffer if sample_size_sniffer > 0 else 1024 * 5))
                if sample:
                    dialect = sniffer.sniff(sample)
                    sep = dialect.delimiter
                    logger.info(f"Separador detectado para CSV: '{sep}'")
                else:
                    logger.warning("Archivo CSV parece vacío o muestra inicial vacía, usando ',' como separador por defecto.")
        except (csv.Error, UnicodeDecodeError) as sniff_err:
            logger.warning(f"No se pudo detectar separador automáticamente ({sniff_err}), usando ',' por defecto.")
        except Exception as sniff_gen_err:
            logger.warning(f"Error inesperado detectando separador ({sniff_gen_err}), usando ',' por defecto.")

        df = pd.read_csv(csv_path, sep=sep, low_memory=False)
        logger.info(f"Datos cargados desde {os.path.basename(csv_path)}: shape={df.shape}, memoria={df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        if df.empty: logger.warning(f"El archivo CSV {os.path.basename(csv_path)} está vacío.")
        return df
    except UnicodeDecodeError:
        logger.warning(f"Error decodificando {os.path.basename(csv_path)} como UTF-8. Intentando con 'latin1'.")
        try:
            df = pd.read_csv(csv_path, sep=sep, encoding='latin1', low_memory=False)
            logger.info(f"Datos cargados con 'latin1': shape={df.shape}")
            return df
        except Exception as e_latin1:
            logger.error(f"Error cargando {os.path.basename(csv_path)} con UTF-8 y latin1: {e_latin1}")
            return None
    except Exception as e:
        logger.error(f"Error cargando {os.path.basename(csv_path)}: {e}\n{traceback.format_exc()}")
        return None

def preprocess(df: pd.DataFrame, cfg: Dict[str, Any]) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series], Optional[List[str]]]:
    """Preprocesa los datos: selecciona features, maneja NaNs y tipos."""
    logger.info("Preprocesando DataFrame...")
    if df is None or df.empty:
        logger.error("DataFrame de entrada vacío. No se puede preprocesar.")
        return None, None, None

    target_col = cfg.get('target_col', 'label')
    if target_col not in df.columns:
        logger.critical(f"Columna target '{target_col}' no encontrada en el CSV.")
        return None, None, None

    feature_cols = [c for c in df.columns if c.startswith('f_')]
    if not feature_cols:
        logger.critical("No se encontraron columnas 'f_*' para usar como features.")
        return None, None, None
    logger.info(f"Encontradas {len(feature_cols)} columnas de features (prefijo 'f_').")

    X = df[feature_cols].copy()
    y = df[target_col].copy()

    # Manejar NaNs en features
    nan_cols = X.columns[X.isnull().any()].tolist()
    if nan_cols:
        logger.warning(f"Se encontraron NaNs en {len(nan_cols)} columnas de features: {nan_cols}.")
        imputer = SimpleImputer(strategy='mean')
        try:
            # Asegurarse que solo se imputen columnas numéricas
            numeric_cols = X.select_dtypes(include=np.number).columns
            non_numeric_cols = X.select_dtypes(exclude=np.number).columns
            if not non_numeric_cols.empty:
                logger.warning(f"Columnas no numéricas encontradas en features: {non_numeric_cols.tolist()}. No serán imputadas por 'mean'.")

            if not numeric_cols.empty:
                cols_to_impute = numeric_cols.intersection(nan_cols)
                if not cols_to_impute.empty:
                    X_imputed_numeric = imputer.fit_transform(X[cols_to_impute])
                    X[cols_to_impute] = pd.DataFrame(X_imputed_numeric, columns=cols_to_impute, index=X.index)
                    logger.info(f"NaNs en {len(cols_to_impute)} columnas numéricas imputados usando la estrategia '{imputer.strategy}'.")
                else:
                    logger.info("No se encontraron NaNs en columnas numéricas.")
            else:
                logger.warning("No se encontraron columnas numéricas en las features para imputar.")

        except Exception as impute_err:
            logger.error(f"Error durante la imputación de NaNs: {impute_err}. Abortando.")
            return None, None, None
    else:
        logger.info("No se encontraron NaNs en las columnas de features.")

    # Convertir features a float64 (o el tipo numérico más apropiado)
    try:
        # Intentar convertir a numérico, forzando errores a NaN
        # Aplicar solo a columnas que no sean ya numéricas para eficiencia
        non_numeric_cols_orig = X.select_dtypes(exclude=np.number).columns
        if not non_numeric_cols_orig.empty:
            logger.info(f"Intentando convertir columnas no numéricas a numérico: {non_numeric_cols_orig.tolist()}")
            X[non_numeric_cols_orig] = X[non_numeric_cols_orig].apply(pd.to_numeric, errors='coerce')
        else:
            logger.info("Todas las features ya eran numéricas inicialmente.")

        # Verificar si se generaron nuevos NaNs por la conversión
        new_nan_cols = X.columns[X.isnull().any()].difference(nan_cols) # NaNs nuevos
        if not new_nan_cols.empty:
            logger.warning(f"Se generaron NaNs al convertir features a numérico en columnas: {new_nan_cols.tolist()}. Re-imputando...")
            # Volver a imputar por si la conversión creó NaNs
            imputer_post_convert = SimpleImputer(strategy='mean')
            numeric_cols_post = X.select_dtypes(include=np.number).columns
            cols_to_reimpute = numeric_cols_post.intersection(new_nan_cols)
            if not cols_to_reimpute.empty:
                X_imputed_post = imputer_post_convert.fit_transform(X[cols_to_reimpute])
                X[cols_to_reimpute] = pd.DataFrame(X_imputed_post, columns=cols_to_reimpute, index=X.index)
                logger.info(f"NaNs generados por conversión en {len(cols_to_reimpute)} columnas re-imputados.")
            else:
                logger.warning("No se encontraron columnas numéricas con NaNs generados por conversión.")

        # Verificar si todas las columnas son ahora numéricas
        non_numeric_final = X.select_dtypes(exclude=np.number).columns
        if not non_numeric_final.empty:
            logger.error(f"Columnas de features no pudieron convertirse a numérico: {non_numeric_final.tolist()}. Abortando.")
            return None, None, None
        else:
            logger.info("Todas las features convertidas a tipos numéricos.")

    except Exception as e:
        logger.critical(f"Error convirtiendo/validando features a numérico: {e}.")
        return None, None, None

    # Validar y limpiar target
    initial_len = len(y)
    if pd.api.types.is_numeric_dtype(y.dtype):
        if y.isnull().any():
            num_nans = y.isnull().sum()
            logger.warning(f"Encontrados {num_nans} NaNs en target numérico '{target_col}'. Eliminando filas.")
            valid_idx = y.dropna().index
            X = X.loc[valid_idx]
            y = y.loc[valid_idx]
            logger.info(f"{initial_len - len(y)} filas eliminadas por NaNs en target.")
    else:
        logger.warning(f"Target '{target_col}' no es numérico. Intentando convertir a numérico (errores -> NaN)...")
        y = pd.to_numeric(y, errors='coerce')
        if y.isnull().any():
            num_nans = y.isnull().sum()
            logger.warning(f"Se generaron/encontraron {num_nans} NaNs al procesar target '{target_col}'. Eliminando filas.")
            valid_idx = y.dropna().index
            X = X.loc[valid_idx]
            y = y.loc[valid_idx]
            logger.info(f"{initial_len - len(y)} filas eliminadas en total durante limpieza de target.")

    if X.empty or y.empty:
        logger.critical("No quedan datos después de manejar NaNs en target.")
        return None, None, None

    # Convertir target a entero
    try:
        y = y.astype(int)
        logger.info(f"Target '{target_col}' convertido a entero.")
        unique_targets = np.unique(y)
        if not np.all(np.isin(unique_targets, [0, 1])):
            logger.warning(f"El target tiene valores diferentes a 0 y 1: {unique_targets}. El script asume clasificación binaria.")
        # Verificar si solo queda una clase
        if len(unique_targets) < 2:
            logger.critical(f"Solo se encontró una clase ({unique_targets}) en el target después del preprocesamiento. No se puede entrenar un clasificador binario.")
            return None, None, None
    except Exception as e:
        logger.critical(f"No se pudo convertir target '{target_col}' a entero: {e}")
        return None, None, None

    logger.info(f"Preprocesamiento finalizado. X shape={X.shape}, y shape={y.shape}")
    # --- CORRECCIÓN AQUÍ ---
    return X, y, feature_cols # ✅ Correct variable name


# --- Funciones de Modelo y Evaluación ---

def create_model(cfg: Dict[str, Any]) -> Optional[Any]:
    """Crea una instancia SIN ENTRENAR del modelo."""
    model_type = cfg['model_type']
    logger.info(f"Creando instancia base del modelo tipo: {model_type}")
    random_state = cfg.get('random_state')
    n_jobs = cfg.get('n_jobs')

    model_params = {}
    # Parámetros comunes a todos los modelos que se pueden setear en el constructor
    common_constructor_params = ['random_state', 'n_jobs']

    # Parámetros específicos por modelo (lista exhaustiva de los aceptados por el constructor)
    allowed_params = {
        'rf': ['n_estimators', 'criterion', 'max_depth', 'min_samples_split', 'min_samples_leaf',
            'min_weight_fraction_leaf', 'max_features', 'max_leaf_nodes', 'min_impurity_decrease',
            'bootstrap', 'oob_score', 'class_weight', 'ccp_alpha', 'max_samples', 'monotonic_cst', 'warm_start', 'verbose'] + common_constructor_params,
        'xgb': ['objective', 'base_score', 'booster', 'callbacks', 'colsample_bylevel', 'colsample_bynode',
                'colsample_bytree', 'device', 'early_stopping_rounds', 'enable_categorical', 'eval_metric',
                'feature_types', 'gamma', 'grow_policy', 'importance_type', 'interaction_constraints',
                'learning_rate', 'max_bin', 'max_cat_threshold', 'max_cat_to_onehot', 'max_delta_step',
                'max_depth', 'max_leaves', 'min_child_weight', 'missing', 'monotonic_constraints',
                'multi_strategy', 'n_estimators', 'num_parallel_tree', 'predictor', 'process_type',
                'random_state', 'reg_alpha', 'reg_lambda', 'sampling_method', 'scale_pos_weight',
                'subsample', 'tree_method', 'validate_parameters', 'verbosity', 'n_jobs', 'use_label_encoder'], # Añadido use_label_encoder explícitamente
        'lgbm': ['boosting_type', 'num_leaves', 'max_depth', 'learning_rate', 'n_estimators', 'subsample_for_bin',
                'objective', 'class_weight', 'min_split_gain', 'min_child_weight', 'min_child_samples',
                'subsample', 'subsample_freq', 'colsample_bytree', 'reg_alpha', 'reg_lambda',
                'importance_type', 'metric', 'force_row_wise', 'force_col_wise', 'verbose', 'device'] + common_constructor_params, # Quitado early_stopping_rounds, metric sí está
    }

    # Filtrar parámetros de la config para que solo incluyan los permitidos por el constructor
    for key in allowed_params.get(model_type, []):
        if key in cfg and cfg[key] is not None: # Solo añadir si existe en config y no es None explícito
            # Corrección especial para n_jobs=-1 en algunos modelos
            if key == 'n_jobs' and model_type in ['lgbm'] and cfg[key] == -1:
                model_params[key] = None # LightGBM prefiere None para usar todos los cores
                logger.info(f"Ajustando n_jobs=-1 a None para {model_type.upper()}")
            else:
                model_params[key] = cfg[key]

    # Añadir/sobrescribir parámetros comunes obligatorios
    model_params['random_state'] = random_state
    if model_type != 'lgbm': # n_jobs ya manejado para lgbm
        model_params['n_jobs'] = n_jobs

    # Ajustar balanceo vs SMOTE
    if not cfg.get('use_smote'):
        if model_type == 'xgb':
            model_params.pop('class_weight', None) # XGB no usa class_weight
            if model_params.get('scale_pos_weight') is None:
                model_params['_needs_scale_pos_weight_calc'] = True # Flag para calcular después
                logger.info("XGBoost sin SMOTE: 'scale_pos_weight' se calculará dinámicamente antes del entrenamiento.")
            else:
                logger.info(f"XGBoost sin SMOTE: Usando scale_pos_weight={model_params['scale_pos_weight']} desde config.")
        elif model_type in ('rf', 'lgbm'):
            model_params.pop('scale_pos_weight', None) # RF/LGBM no usan scale_pos_weight
            if cfg.get('class_weight') == 'balanced': # Comprobar si se pidió explícitamente
                model_params['class_weight'] = 'balanced'
                logger.info(f"{model_type.upper()} sin SMOTE: Usando class_weight='balanced' desde config.")
            else:
                # Si no es 'balanced' o no está en config, asegurar que sea None
                model_params['class_weight'] = None
                logger.info(f"{model_type.upper()} sin SMOTE: Usando class_weight=None (default).")
    else:
        # Si SMOTE está activado, forzar los parámetros de balanceo interno a neutro
        logger.info(f"SMOTE activado, configurando balanceo interno de {model_type.upper()} a None/1.0.")
        if 'class_weight' in model_params: model_params['class_weight'] = None
        if 'scale_pos_weight' in model_params: model_params['scale_pos_weight'] = 1.0
        # Quitar el flag de cálculo si existía
        model_params.pop('_needs_scale_pos_weight_calc', None)

    # Defaults/Correcciones específicas post-procesamiento
    if model_type == 'xgb':
        model_params.setdefault('use_label_encoder', False) # Requerido por versiones recientes
        model_params.setdefault('verbosity', 0) # 0 = silent, 1 = warning, 2 = info, 3 = debug
        # Asegurar eval_metric si ES está activado
        if 'early_stopping_rounds' in model_params and model_params['early_stopping_rounds'] is not None:
            model_params.setdefault('eval_metric', 'auc') # Necesario para ES
            logger.info(f"Early stopping configurado para XGBoost, asegurando eval_metric='{model_params['eval_metric']}' en constructor.")
    elif model_type == 'lgbm':
        model_params.setdefault('verbosity', -1) # -1 = fatal, 0 = error/warn, 1 = info, 2 = debug
        if model_params.get('max_depth') is None: model_params['max_depth'] = -1 # Default de LGBM para sin límite
        # 'early_stopping_rounds' NO es un parámetro del constructor de LGBMClassifier
        model_params.pop('early_stopping_rounds', None)
        # Asegurar 'metric' si ES se va a usar (se usa en fit via callbacks)
        if cfg.get('early_stopping_rounds') is not None:
            model_params.setdefault('metric', 'auc') # Necesario para el callback de ES
            logger.info(f"Early stopping configurado para LightGBM, asegurando metric='{model_params['metric']}' en constructor.")
    elif model_type == 'rf':
        model_params.setdefault('verbose', 0) # 0=no logs
        if model_params.get('max_depth') == -1: model_params['max_depth'] = None # None es el default de RF para sin límite
        # RF no soporta estos parámetros
        model_params.pop('early_stopping_rounds', None)
        model_params.pop('eval_metric', None)
        model_params.pop('scale_pos_weight', None)


    logger.info(f"Parámetros finales para instancia {model_type.upper()}: {model_params}")

    model = None
    try:
        # Extraer el flag antes de pasarlo al constructor
        needs_calc_spw = model_params.pop('_needs_scale_pos_weight_calc', False)

        if model_type == 'rf':
            model = RandomForestClassifier(**model_params)
        elif model_type == 'xgb':
            model = XGBClassifier(**model_params)
        elif model_type == 'lgbm':
            model = LGBMClassifier(**model_params)
        if model is None: raise ValueError(f"Tipo de modelo '{model_type}' no reconocido o falló la instanciación.")

        # Volver a añadir el flag al objeto modelo si era necesario (para usarlo antes de fit)
        if needs_calc_spw:
            model._needs_scale_pos_weight_calc = True

    except TypeError as e:
        logger.error(f"Error de tipo al crear {model_type.upper()}. Parámetros inválidos? {model_params}. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"Error inesperado creando {model_type.upper()}: {e}")
        return None

    return model


def get_best_iteration(model: Any) -> Optional[int]:
    """Intenta obtener la mejor iteración de Early Stopping."""
    # Orden de preferencia basado en observaciones comunes
    if hasattr(model, 'best_iteration_') and model.best_iteration_ is not None: return model.best_iteration_ # LGBM
    if hasattr(model, 'best_iteration') and model.best_iteration is not None: return model.best_iteration # Older XGB?
    if hasattr(model, 'best_ntree_limit') and isinstance(model.best_ntree_limit, int): return model.best_ntree_limit # XGB
    # A veces está en el booster interno (especialmente con API scikit-learn de XGB)
    booster = getattr(model, 'booster_', getattr(model, '_Booster', None)) # Intentar acceder al booster interno
    if booster and hasattr(booster, 'best_iteration') and booster.best_iteration is not None: return booster.best_iteration
    return None

def plot_and_log_roc_curve(y_true, y_proba, model_name, run_id, report_dir, mlflow_instance):
    """Genera, guarda y loggea la curva ROC en MLflow."""
    try:
        # Asegurar que y_true y y_proba sean arrays de numpy para roc_curve
        y_true_np = np.asarray(y_true)
        y_proba_np = np.asarray(y_proba)
        fpr, tpr, _ = roc_curve(y_true_np, y_proba_np)
        roc_auc_val = auc(fpr, tpr)
        fig, ax = plt.subplots()
        ax.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc_val:.4f})')
        ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        ax.set_xlim([0.0, 1.0]); ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate')
        ax.set_title(f'{model_name} ROC Curve (Holdout Set)')
        ax.legend(loc="lower right"); plt.tight_layout()
        filename = f"{run_id}_{model_name}_holdout_roc_curve.png"
        filepath = os.path.join(report_dir, filename)
        plt.savefig(filepath); plt.close(fig)
        mlflow_instance.log_artifact(filepath)
        logger.info(f"Curva ROC guardada y registrada: {filename}")
        return roc_auc_val
    except Exception as e:
        logger.error(f"Error generando/guardando curva ROC: {e}")
        return None

def plot_and_log_confusion_matrix(y_true, y_pred, threshold, model_name, run_id, report_dir, mlflow_instance):
    """Genera, guarda y loggea la matriz de confusión en MLflow."""
    try:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        # Manejo robusto del unpacking de CM
        if cm.size == 4: tn, fp, fn, tp = cm.ravel()
        elif cm.size == 1: # Solo una clase predicha/real
            if np.unique(y_true)[0] == 0: tn, fp, fn, tp = cm[0,0], 0, 0, 0
            else: tn, fp, fn, tp = 0, 0, 0, cm[0,0]
        else: # Caso inesperado
            tn, fp, fn, tp = 0, 0, 0, 0
            logger.warning(f"Matriz de confusión con tamaño inesperado {cm.size} para umbral {threshold}. CM: {cm}")

        fig, ax = plt.subplots()
        cax = ax.matshow(cm, cmap=plt.cm.Blues)
        fig.colorbar(cax)
        thresh_color = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                text_color = 'white' if cm[i, j] > thresh_color else 'black'
                ax.text(j, i, f'{cm[i, j]}', va='center', ha='center', color=text_color)
        ax.set_xticks(np.arange(2)); ax.set_yticks(np.arange(2))
        ax.set_xticklabels(['Pred 0', 'Pred 1']); ax.set_yticklabels(['True 0', 'True 1'])
        ax.set_xlabel('Predicted Label'); ax.set_ylabel('True Label')
        ax.set_title(f'{model_name} CM (Holdout, Thresh={threshold:.2f})\nTN={tn}, FP={fp}, FN={fn}, TP={tp}')
        plt.tight_layout()
        filename = f"{run_id}_holdout_cm_th_{threshold:.2f}.png"
        filepath = os.path.join(report_dir, filename)
        plt.savefig(filepath); plt.close(fig)
        mlflow_instance.log_artifact(filepath)
    except Exception as e:
        logger.error(f"Error generando/guardando matriz de confusión (Th={threshold:.2f}): {e}")

def evaluate_holdout_thresholds(y_true, y_proba, thresholds, model_name, run_id, report_dir, mlflow_instance) -> Dict[float, Dict[str, Any]]:
    """Evalúa predicciones en holdout para múltiples umbrales."""
    results = {}
    logger.info(f"--- Evaluando Holdout con Umbrales: {thresholds} ---")
    for threshold in thresholds:
        try:
            y_pred_thresh = (y_proba >= threshold).astype(int)
            accuracy = accuracy_score(y_true, y_pred_thresh)
            # Calcular métricas por clase (0 y 1)
            precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred_thresh, average=None, labels=[0, 1], zero_division=0)
            # Calcular métricas macro
            precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(y_true, y_pred_thresh, average='macro', zero_division=0)
            # Obtener CM y TN/FP/FN/TP
            cm = confusion_matrix(y_true, y_pred_thresh, labels=[0, 1])
            if cm.size == 4: tn, fp, fn, tp = cm.ravel()
            elif cm.size == 1: tn, fp, fn, tp = (cm[0,0], 0, 0, 0) if np.unique(y_true)[0] == 0 else (0, 0, 0, cm[0,0])
            else: tn, fp, fn, tp = 0,0,0,0; logger.warning(f"Matriz de confusión inesperada {cm.shape} para umbral {threshold}")

            metrics_th = {
                "accuracy": accuracy, "precision_macro": precision_macro, "recall_macro": recall_macro, "f1_macro": f1_macro,
                "precision_0": precision[0] if len(precision)>0 else 0, "recall_0": recall[0] if len(recall)>0 else 0,
                "f1_0": f1[0] if len(f1)>0 else 0, "support_0": support[0] if len(support)>0 else 0,
                "precision_1": precision[1] if len(precision)>1 else 0, "recall_1": recall[1] if len(recall)>1 else 0,
                "f1_1": f1[1] if len(f1)>1 else 0, "support_1": support[1] if len(support)>1 else 0,
                "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn), # Convertir a int estándar
            }
            results[threshold] = metrics_th
            prefix = f"th_{threshold:.2f}_"
            # Loggear métricas con prefijo de umbral
            mlflow_instance.log_metrics({prefix + k: v for k, v in metrics_th.items()})
            logger.info(f"Holdout (Th={threshold:.2f}): Acc={accuracy:.4f}, F1M={f1_macro:.4f}, Recall_1={metrics_th['recall_1']:.4f}, Precision_1={metrics_th['precision_1']:.4f}, TP={tp}, FP={fp}")
            # Generar reporte de clasificación
            report_str = classification_report(y_true, y_pred_thresh, target_names=['Class 0', 'Class 1'], zero_division=0)
            report_filename = f"{run_id}_holdout_report_th_{threshold:.2f}.txt"
            report_path = os.path.join(report_dir, report_filename)
            with open(report_path, 'w', encoding='utf-8') as f: f.write(report_str)
            mlflow_instance.log_artifact(report_path)
            # Generar y loggear CM
            plot_and_log_confusion_matrix(y_true, y_pred_thresh, threshold, model_name, run_id, report_dir, mlflow_instance)
        except Exception as e:
            logger.error(f"Error evaluando umbral {threshold:.2f}: {e}")
            results[threshold] = {} # Dejar vacío si falla
    return results

def evaluate_model(
    model_instance: Any, X_train: pd.DataFrame, y_train: pd.Series,
    X_holdout: pd.DataFrame, y_holdout: pd.Series, cfg: Dict[str, Any],
    feature_names: List[str], X_train_original: Optional[pd.DataFrame] = None,
    y_train_original: Optional[pd.Series] = None
) -> Tuple[Optional[Any], Dict[str, Any], Optional[str]]: # Added Optional[str] for run_id return
    """Orquesta entrenamiento, evaluación y logging en MLflow."""
    model_type = cfg['model_type']
    model_name = model_type.upper()
    use_randomsearch = cfg.get('use_randomsearch', False) and 'param_dist' in cfg
    n_iter = cfg.get('n_iter', 10)
    early_stopping_rounds = cfg.get('early_stopping_rounds')
    use_optimization = use_randomsearch

    logger.info(f"--- Iniciando Entrenamiento y Evaluación: {model_name} ---")
    logger.info(f"Optimización con RandomizedSearchCV: {'Sí (n_iter=' + str(n_iter) + ')' if use_optimization else 'No'}")

    es_configured = early_stopping_rounds is not None and model_type in ('xgb', 'lgbm')
    es_msg = f'Sí (rondas={early_stopping_rounds})' if es_configured else 'No Configurado'
    logger.info(f"Early Stopping Configurado: {es_msg}")


    thresholds_to_test = cfg.get('thresholds_to_test', [0.5])
    logger.info(f"Umbrales a probar en Holdout: {thresholds_to_test}")

    final_model: Optional[Any] = None
    best_params_found: Dict[str, Any] = model_instance.get_params() if model_instance else {}
    holdout_metrics: Dict[str, Any] = {}
    optimization_time: float = 0.0
    training_time: float = 0.0
    run_id_for_summary = None # Variable para guardar el Run ID

    if X_train is None or X_train.empty or y_train is None or y_train.empty or \
    X_holdout is None or X_holdout.empty or y_holdout is None or y_holdout.empty:
        logger.error("Datos de entrenamiento o Holdout vacíos. Abortando.")
        return None, {}, None # Return None for run_id too
    if model_instance is None: # Chequeo adicional
        logger.error("Instancia base del modelo es None. Abortando.")
        return None, {}, None

    # Calcular scale_pos_weight si es necesario ANTES de RS o fit directo
    if model_type == 'xgb' and getattr(model_instance, '_needs_scale_pos_weight_calc', False):
        y_target_for_calc = y_train_original if y_train_original is not None else y_train
        try:
            counts = np.bincount(y_target_for_calc.astype(int))
            if len(counts) == 2 and counts[1] > 0:
                scale_pos_weight_to_use = counts[0] / counts[1]
                logger.info(f"XGBoost: Calculado scale_pos_weight dinámicamente: {scale_pos_weight_to_use:.4f}")
            else:
                scale_pos_weight_to_use = 1.0
                logger.warning(f"No se pudo calcular scale_pos_weight (clases={counts}). Usando 1.0.")
            # Actualizar la instancia base para que se use en RS o fit directo
            model_instance.set_params(scale_pos_weight=scale_pos_weight_to_use)
            best_params_found['scale_pos_weight'] = scale_pos_weight_to_use # Actualizar params base
            delattr(model_instance, '_needs_scale_pos_weight_calc') # Eliminar el flag
        except Exception as e:
            logger.error(f"Error calculando scale_pos_weight: {e}. Usando 1.0")
            model_instance.set_params(scale_pos_weight=1.0)
            if hasattr(model_instance, '_needs_scale_pos_weight_calc'): delattr(model_instance, '_needs_scale_pos_weight_calc')

    # --- MLflow Setup dentro de evaluate_model ---
    mlflow_experiment_name = cfg.get('experiment_name', f"FraudDetection_{model_name}")
    mlflow_experiment_name = mlflow_experiment_name.replace("{model_type}", model_name) # Asegurar reemplazo
    # El experimento ya debe estar creado/seteado en main()

    try:
        with mlflow.start_run(run_name=f"{model_name}_Run_{datetime.now().strftime('%Y%m%d_%H%M%S')}") as run:
            run_id = run.info.run_id
            run_id_for_summary = run_id # Guardar para resumen final
            logger.info(f"MLflow Run ID: {run_id} (Experimento: '{mlflow_experiment_name}')")
            mlflow.log_param("model_type", model_type)
            mlflow.log_param("run_id", run_id)

            # Loggear parámetros iniciales de config y datos
            params_to_log = {k: v for k, v in cfg.items() if k not in ['param_dist', 'thresholds_to_test'] and isinstance(v, (str, int, float, bool, type(None)))}
            if 'param_dist' in cfg: params_to_log['param_dist_str'] = str({k: str(v.__class__.__name__) for k,v in cfg['param_dist'].items()}) # Log dist names
            params_to_log.update({
                'num_features': len(feature_names) if feature_names else X_train.shape[1],
                'training_samples_original': len(y_train_original) if y_train_original is not None else len(y_train),
                'training_samples_final': len(y_train), # Post-SMOTE if applied
                'holdout_samples': len(X_holdout),
                'optimization_method': 'RandomSearch' if use_optimization else 'DirectFit',
                'early_stopping_configured': es_configured,
                'gpu_enabled_explicitly': (cfg.get('tree_method') == 'gpu_hist' if model_type == 'xgb' else cfg.get('device') == 'gpu' if model_type == 'lgbm' else False),
                'smote_applied': cfg.get('use_smote', False) # Loggear si SMOTE se intentó/aplicó
            })
            mlflow.log_params(params_to_log)
            if feature_names: mlflow.log_param("feature_names_list", ", ".join(feature_names))
            mlflow.log_param("thresholds_tested_str", str(thresholds_to_test))
            # --- Variable para loggear si se intentó ES en RS ---
            es_attempted_rs_log = False

            # Optimización (Randomized Search)
            if use_optimization:
                param_dist = cfg.get('param_dist', {})
                if not param_dist:
                    logger.warning("RandomizedSearch habilitado pero param_dist vacío o no encontrado. Saltando optimización.")
                    use_optimization = False # Cambiar a False para que entre en fit directo
                else:
                    logger.info(f"Iniciando RandomizedSearchCV para {model_name}...")
                    cv_strategy = StratifiedKFold(n_splits=cfg.get('cv_folds'), shuffle=True, random_state=cfg.get('random_state'))
                    # Usar la instancia base (potencialmente con scale_pos_weight ya calculado)
                    estimator_for_search = model_instance

                    # Asegurarse que los parámetros fijos (ej: tree_method, device) no estén en param_dist si deben ser fijos
                    fixed_params = {}
                    params_to_remove_from_dist = []
                    if model_type == 'xgb':
                        if 'tree_method' in cfg and cfg['tree_method'] == 'gpu_hist':
                            fixed_params['tree_method'] = 'gpu_hist'
                            params_to_remove_from_dist.append('tree_method')
                        if 'eval_metric' in cfg: # Asegurar métrica fija si está en config
                            fixed_params['eval_metric'] = cfg['eval_metric']
                            params_to_remove_from_dist.append('eval_metric')
                        if 'early_stopping_rounds' in cfg: # Asegurar ES fijo si está en config
                            fixed_params['early_stopping_rounds'] = cfg['early_stopping_rounds']
                            # No necesita removerse de param_dist, ya que no suele estar ahí
                    elif model_type == 'lgbm':
                        if 'device' in cfg and cfg['device'] == 'gpu':
                            fixed_params['device'] = 'gpu'
                            params_to_remove_from_dist.append('device')
                        if 'metric' in cfg: # Asegurar métrica fija si está en config
                            fixed_params['metric'] = cfg['metric']
                            params_to_remove_from_dist.append('metric')

                    # Crear la distribución final eliminando los fijos y añadiéndolos al estimador base
                    final_param_dist = {k: v for k, v in param_dist.items() if k not in params_to_remove_from_dist}
                    if fixed_params:
                        logger.info(f"Aplicando parámetros fijos al estimador base para RS: {fixed_params}")
                        estimator_for_search.set_params(**fixed_params)

                    if not final_param_dist:
                        logger.error("Distribución de parámetros para RandomizedSearch quedó vacía después de aplicar fijos. Abortando RS.")
                        return None, {}, run_id_for_summary

                    search_cv = RandomizedSearchCV(
                        estimator=estimator_for_search, param_distributions=final_param_dist, n_iter=n_iter,
                        cv=cv_strategy, scoring='roc_auc', n_jobs=cfg.get('n_jobs'), verbose=1,
                        random_state=cfg.get('random_state'), error_score='raise' # Raise error instead of failing silently
                    )

                    # Preparación Early Stopping en RS
                    fit_params_rs = {}
                    eval_set_rs = None
                    # Usar el valor de ES configurado en el modelo base (puede venir de config)
                    local_early_stopping_rounds = getattr(estimator_for_search, 'early_stopping_rounds', None)

                    if local_early_stopping_rounds is not None and model_type in ('lgbm', 'xgb'):
                        logger.info(f"Preparando eval_set para ES ({local_early_stopping_rounds} rondas) dentro de RS ({model_name}).")
                        es_attempted_rs_log = True # Marcar intento
                        try:
                            # Crear eval_set a partir del X/y_train actual (puede ser post-SMOTE)
                            X_train_rs_fit, X_val_rs_fit, y_train_rs_fit, y_val_rs_fit = train_test_split(
                                X_train, y_train, test_size=0.15, random_state=cfg['random_state'], stratify=y_train
                            )
                            eval_set_rs = [(X_val_rs_fit, y_val_rs_fit)]
                            logger.info(f"Creado eval_set interno para ES en RS: {len(y_val_rs_fit)} muestras.")

                            # Configuración específica para LGBM y XGBoost dentro de RS
                            if model_type == 'lgbm' and LGBM_AVAILABLE:
                                # Pasar callbacks para ES en LGBM
                                fit_params_rs['callbacks'] = [lgb.early_stopping(local_early_stopping_rounds, verbose=False)]
                                # Necesario que LGBM sepa qué métrica usar para ES via callbacks
                                lgbm_metric_rs = getattr(estimator_for_search, 'metric', 'auc') # Usar métrica del modelo base
                                fit_params_rs['eval_metric'] = lgbm_metric_rs
                                fit_params_rs['eval_set'] = eval_set_rs
                                logger.info(f"Añadido 'callbacks', 'eval_set' y 'eval_metric={fit_params_rs['eval_metric']}' a fit_params para LightGBM en RS.")

                            if model_type == 'xgb' and XGBOOST_AVAILABLE:
                                # --- CORRECCIÓN AQUÍ (v5.8.8) ---
                                # Para XGBoost, SÓLO pasar eval_set y verbose a fit() via fit_params.
                                # early_stopping_rounds debe estar en la inicialización del modelo.
                                fit_params_rs = {
                                    'eval_set': eval_set_rs,
                                    'verbose': False # Suprimir logs internos de XGBoost fit
                                }
                                logger.info(f"Configured 'eval_set' and 'verbose=False' for XGBoost in RandomizedSearchCV fit_params. Early stopping handled by model init.")

                        except Exception as es_rs_err:
                            logger.warning(f"Error creando eval_set para ES en RS: {es_rs_err}. ES puede fallar o no aplicarse.")
                            fit_params_rs = {} # Reset fit_params si falla la preparación
                            es_attempted_rs_log = False # Marcar fallo
                    # Loggear el intento (True o False)
                    mlflow.log_param("early_stopping_in_randomsearch_attempted", es_attempted_rs_log)


                    # Ejecutar RandomizedSearchCV.fit()
                    try:
                        fit_param_keys_str = ", ".join(fit_params_rs.keys()) if fit_params_rs else "Ninguno"
                        logger.info(f"Iniciando RS.fit() en {search_cv.n_jobs} jobs (pasando fit_params: [{fit_param_keys_str}])...")
                        start_opt_time = time.time()
                        with warnings.catch_warnings(): # Context manager para warnings
                            warnings.filterwarnings("ignore", category=UserWarning, module='joblib')
                            warnings.filterwarnings("ignore", category=FutureWarning, module='lightgbm')
                            # Pasar X_train (puede ser post-SMOTE) y y_train (puede ser post-SMOTE)
                            search_cv.fit(X_train, y_train, **fit_params_rs)
                        optimization_time = time.time() - start_opt_time
                        logger.info(f"RS completado en {optimization_time:.2f} seg.")

                        final_model = search_cv.best_estimator_
                        best_params_found = search_cv.best_params_ # Guardar solo los params optimizados
                        logger.info(f"Mejor puntuación CV (roc_auc): {search_cv.best_score_:.4f}")
                        logger.info(f"Mejores parámetros encontrados por RS: {best_params_found}")

                        # Loggear resultados de RS
                        mlflow.log_metric("randomsearch_best_cv_roc_auc", search_cv.best_score_)
                        best_params_loggable = {f"best_{k}": str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v for k, v in best_params_found.items()}
                        mlflow.log_params(best_params_loggable)
                        mlflow.log_metric("optimization_time_sec", optimization_time)
                        training_time = optimization_time # Consider RS time as training time

                        # Actualizar la instancia final del modelo con los parámetros fijos si los hubo
                        if fixed_params:
                            logger.info(f"Aplicando parámetros fijos al mejor modelo encontrado por RS: {fixed_params}")
                            final_model.set_params(**fixed_params)

                    except Exception as e:
                        logger.error(f"Error durante RandomizedSearchCV: {e}\n{traceback.format_exc()}")
                        mlflow.log_param("randomsearch_error", str(e))
                        mlflow.set_tag("training_status", "failed_randomsearch")
                        return None, {}, run_id_for_summary # Devolver run_id aunque falle aquí

            # Entrenamiento Directo (si NO se usó optimización)
            if not use_optimization: # Solo si RS no se ejecutó o se saltó
                logger.info(f"Entrenando modelo final {model_name} directamente (sin optimización)...")
                final_model = model_instance # Usar la instancia base

                params_loggable_direct = {f"final_fit_{k}": str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v for k, v in final_model.get_params().items()}
                logger.info(f"Usando parámetros para fit directo: {params_loggable_direct}")
                mlflow.log_params(params_loggable_direct)

                # Preparación Early Stopping para fit directo
                fit_params = {}
                eval_set = None
                X_to_fit, y_to_fit = X_train, y_train # Usar los datos de entrada (pueden ser post-SMOTE)
                es_direct_fit_attempted = False
                # Usar el valor de ES configurado en el modelo base
                local_early_stopping_rounds_direct = getattr(final_model, 'early_stopping_rounds', None)

                if local_early_stopping_rounds_direct is not None and model_type in ('xgb', 'lgbm'):
                    logger.info(f"Preparando ES para fit directo (rondas={local_early_stopping_rounds_direct})")
                    es_direct_fit_attempted = True
                    try:
                        # Crear conjunto de validación del CONJUNTO DE ENTRENAMIENTO ACTUAL (puede ser post-SMOTE)
                        X_train_fit, X_val_fit, y_train_fit, y_val_fit = train_test_split(
                            X_train, y_train, test_size=0.15, random_state=cfg['random_state'], stratify=y_train
                        )
                        eval_set = [(X_val_fit, y_val_fit)]
                        X_to_fit, y_to_fit = X_train_fit, y_train_fit # Entrenar en el subset más pequeño
                        logger.info(f"Creado eval_set para ES (fit directo): {len(y_val_fit)} muestras.")

                        if model_type == 'lgbm' and LGBM_AVAILABLE:
                            fit_params['callbacks'] = [lgb.early_stopping(local_early_stopping_rounds_direct, verbose=False)]
                            lgbm_metric_direct = getattr(final_model, 'metric', 'auc') # Usar métrica del modelo
                            fit_params['eval_metric'] = lgbm_metric_direct
                            fit_params['eval_set'] = eval_set
                        elif model_type == 'xgb' and XGBOOST_AVAILABLE:
                            # Pasar SOLO eval_set y verbose a fit()
                            fit_params['eval_set'] = eval_set
                            fit_params['verbose'] = False # Para suprimir logs de cada ronda
                            # early_stopping_rounds ya está en la inicialización del modelo

                    except Exception as es_err:
                        logger.error(f"Error preparando ES (fit directo): {es_err}. Entrenando sin ES en todo el set de train.")
                        eval_set = None; fit_params = {}; X_to_fit, y_to_fit = X_train, y_train
                        es_direct_fit_attempted = False
                mlflow.log_param("early_stopping_in_direct_fit_attempted", es_direct_fit_attempted)

                # Realizar el fit (SOLO si no se usó RS)
                try:
                    fit_param_keys_direct_str = ", ".join(fit_params.keys()) if fit_params else "Ninguno"
                    logger.info(f"Iniciando fit directo {model_name} (pasando fit_params: [{fit_param_keys_direct_str}])...")
                    start_train_time = time.time()
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=FutureWarning, module='lightgbm')
                        # Entrenar con X_to_fit, y_to_fit (que pueden ser subsets si ES se activó)
                        final_model.fit(X_to_fit, y_to_fit, **fit_params)
                    training_time = time.time() - start_train_time
                    logger.info(f"Modelo final entrenado directamente en {training_time:.2f} seg.")
                    mlflow.log_metric("direct_training_time_sec", training_time)

                    # Loggear mejor iteración si ES se aplicó en fit directo
                    if es_direct_fit_attempted and eval_set:
                        best_iter = get_best_iteration(final_model)
                        if best_iter is not None:
                            logger.info(f"ES (Fit Directo) activado. Mejor iteración: {best_iter}")
                            mlflow.log_metric("direct_fit_early_stopping_best_iteration", best_iter)
                        else: logger.warning("ES (Fit Directo) usado, pero no se pudo obtener la mejor iteración.")
                except Exception as e:
                    logger.error(f"Error entrenando {model_name} directamente: {e}\n{traceback.format_exc()}")
                    mlflow.log_param("training_error", str(e))
                    mlflow.set_tag("training_status", "failed_final_fit")
                    return None, {}, run_id_for_summary

            # Evaluación en Holdout
            if final_model is None:
                logger.error("Modelo final es None (falló RS o fit directo). Abortando evaluación.")
                mlflow.set_tag("training_status", "failed_model_is_none")
                return None, {}, run_id_for_summary

            logger.info(f"Evaluando modelo final en Holdout ({len(X_holdout)} muestras)...")
            holdout_eval_time_start = time.time()
            try:
                y_proba_holdout = final_model.predict_proba(X_holdout)[:, 1]
                holdout_roc_auc = plot_and_log_roc_curve(y_holdout, y_proba_holdout, model_name, run_id, REPORT_DIR, mlflow)
                if holdout_roc_auc is not None:
                    logger.info(f"{model_name} Holdout AUC General: {holdout_roc_auc:.4f}")
                    mlflow.log_metric("holdout_roc_auc_overall", holdout_roc_auc)
                else:
                    logger.warning("Cálculo de AUC en holdout falló.")

                threshold_results = evaluate_holdout_thresholds(y_holdout, y_proba_holdout, thresholds_to_test, model_name, run_id, REPORT_DIR, mlflow)
                default_threshold = cfg.get('classification_threshold', 0.5)
                # Guardar métricas del umbral default si existen
                if default_threshold in threshold_results and threshold_results[default_threshold]:
                    holdout_metrics = {f"holdout_{k}": v for k, v in threshold_results[default_threshold].items()}
                    if holdout_roc_auc is not None: holdout_metrics["holdout_roc_auc_overall"] = holdout_roc_auc
                elif thresholds_to_test: # Si el default falló pero otros no, tomar el primero que funcionó
                    first_valid_thresh = next((t for t in thresholds_to_test if t in threshold_results and threshold_results[t]), None)
                    if first_valid_thresh:
                        logger.warning(f"Métricas para umbral default ({default_threshold}) no disponibles. Usando métricas de umbral {first_valid_thresh} como referencia.")
                        holdout_metrics = {f"holdout_{k}": v for k, v in threshold_results[first_valid_thresh].items()}
                        if holdout_roc_auc is not None: holdout_metrics["holdout_roc_auc_overall"] = holdout_roc_auc
                    else:
                        logger.error("Evaluación de todos los umbrales en holdout falló.")

            except Exception as e:
                logger.error(f"Error evaluación Holdout: {e}\n{traceback.format_exc()}")
                mlflow.log_param("holdout_error", str(e)); mlflow.set_tag("training_status", "failed_holdout_eval")
            finally:
                holdout_eval_time = time.time() - holdout_eval_time_start
                logger.info(f"Evaluación Holdout completada en {holdout_eval_time:.2f} seg.")
                mlflow.log_metric("holdout_evaluation_time_sec", holdout_eval_time)

            # Guardar y Registrar Modelo Final
            if final_model:
                logger.info("Guardando y registrando el modelo final...")
                # Loggear los parámetros REALES del modelo final (combinando optimizados y fijos)
                final_params_used_loggable = {f"final_used_{k}": str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v for k, v in final_model.get_params().items()}
                mlflow.log_params(final_params_used_loggable)

                # Loggear la mejor iteración del modelo FINAL (puede haber venido de ES en RS o en fit directo)
                best_iter_final = get_best_iteration(final_model)
                if best_iter_final is not None:
                    logger.info(f"Modelo final usó {best_iter_final} iteraciones (posiblemente por ES).")
                    mlflow.log_metric("final_model_best_iteration", best_iter_final)

                model_filename = f"{run_id}_{model_name}_model.joblib"
                local_model_path = os.path.join(MODEL_DIR, model_filename)
                try:
                    joblib.dump(final_model, local_model_path)
                    logger.info(f"Modelo guardado localmente: {local_model_path}")
                    mlflow.log_artifact(local_model_path, artifact_path="model_joblib")
                except Exception as e: logger.error(f"Error guardando modelo local: {e}")

                try:
                    # Usar X_train_original para la firma (datos antes de SMOTE)
                    X_sig_source = X_train_original if X_train_original is not None else X_train
                    signature, input_example = None, None
                    if X_sig_source is not None and not X_sig_source.empty:
                        try:
                            # Usar feature_names que viene como argumento a evaluate_model
                            cols_sig = feature_names if feature_names else X_sig_source.columns.tolist()
                            # Asegurar que las columnas existan en la fuente de firma
                            cols_sig = [c for c in cols_sig if c in X_sig_source.columns]
                            if not cols_sig:
                                logger.warning("No se encontraron columnas válidas para la firma MLflow.")
                            else:
                                sample_size = min(5, len(X_sig_source))
                                # Usar el mismo random state para la muestra
                                X_sig_input = X_sig_source[cols_sig].sample(sample_size, random_state=cfg.get('random_state'))
                                # Predecir con el modelo final entrenado
                                y_pred_sig = final_model.predict(X_sig_input)
                                signature = infer_signature(X_sig_input, y_pred_sig)
                                # Crear input_example del primer registro de la muestra
                                input_example = X_sig_input.iloc[[0]].to_dict(orient='records')[0]
                                logger.info("Firma MLflow inferida.")
                        except Exception as sig_err: logger.error(f"Error infiriendo firma MLflow: {sig_err}")

                    should_register = cfg.get('register_models', False)
                    reg_model_name = None
                    if should_register:
                        # Construir nombre del modelo registrado desde el nombre del experimento
                        exp_name_final = mlflow_experiment_name # Usar el nombre del experimento actual
                        # Asegurar nombre válido para registro
                        reg_model_name = f"{exp_name_final}".replace(" ", "_").replace("/", "-").replace("\\", "-")
                        logger.info(f"Intentando registrar modelo como: {reg_model_name}")

                    mlflow.sklearn.log_model(sk_model=final_model, artifact_path="model", signature=signature,
                                            registered_model_name=reg_model_name, input_example=input_example)
                    if reg_model_name and should_register: logger.info(f"Modelo registrado en MLflow: {reg_model_name}")
                    else: logger.info("Modelo loggeado en MLflow Run (no registrado o registro desactivado).")
                except Exception as e:
                    logger.error(f"Error loggeando/registrando modelo con MLflow: {e}\n{traceback.format_exc()}")
                    mlflow.log_param("mlflow_log_model_error", str(e))

                mlflow.set_tag("training_status", "completed")
                logger.info(f"--- Entrenamiento y Evaluación {model_name} Finalizada ---")
            else:
                # Esto no debería ocurrir si la lógica anterior es correcta, pero por seguridad
                mlflow.set_tag("training_status", "failed_final_model_missing_post_eval")
                logger.error(f"--- Evaluación {model_name} Fallida (Modelo final se perdió inesperadamente) ---")
                return None, holdout_metrics, run_id_for_summary

    except Exception as e:
        logger.error(f"Error fatal en el bloque principal de evaluate_model: {e}\n{traceback.format_exc()}")
        try:
            if mlflow.active_run():
                # Asegurarse de que run_id_for_summary tenga el ID si el run se inició
                current_run_info = mlflow.active_run().info
                run_id_for_summary = current_run_info.run_id
                mlflow.log_param("evaluate_function_error", str(e))
                mlflow.set_tag("training_status", "failed_evaluate_function")
                mlflow.end_run(status='FAILED') # Terminar el run como fallido
        except Exception as mlflow_err: logger.error(f"Error adicional cerrando run MLflow tras error: {mlflow_err}")
        return None, {}, run_id_for_summary # Devolver run_id si se obtuvo, aunque falle

    # Devolver el modelo, métricas y run_id al final
    return final_model, holdout_metrics, run_id_for_summary


# --- Flujo Principal ---
def main():
    """Función principal que orquesta carga, preprocesamiento, entrenamiento y evaluación."""
    script_version = "5.8.9 - Corregido NameError en preprocess" # Actualizar versión
    logger.info(f"=== Inicio del script de entrenamiento ({script_version}) ===")
    script_start_time = time.time()

    # Establecer MLflow Tracking URI
    mlflow_tracking_uri = "file:///C:/Users/RayRay/mlruns"
    try:
        uri_path_base = mlflow_tracking_uri.replace("file:///", "")
        if platform.system() == "Windows":
            uri_path_base = uri_path_base.replace("/", os.sep)
        if not os.path.exists(uri_path_base):
            logger.warning(f"La ruta base para MLflow URI no existe: {uri_path_base}. MLflow intentará crearla.")
            # os.makedirs(uri_path_base, exist_ok=True) # Descomentar si quieres crearla

        mlflow.set_tracking_uri(mlflow_tracking_uri)
        logger.info(f"MLflow tracking URI establecida en: {mlflow.get_tracking_uri()}")
    except Exception as e:
        logger.error(f"Error estableciendo MLflow tracking URI a '{mlflow_tracking_uri}': {e}")
        logger.warning("Continuando con la configuración por defecto de MLflow (./mlruns)")

    # Carga de Configuración
    cfg = load_config()
    if not cfg: sys.exit(1)

    # Configurar Experimento MLflow
    mlflow_experiment_name = cfg.get('experiment_name', f"Default_{cfg.get('model_type', 'Model')}_Experiment")
    mlflow_experiment_name = mlflow_experiment_name.replace("{model_type}", cfg.get('model_type', 'Model').upper())
    logger.info(f"Nombre del experimento MLflow: {mlflow_experiment_name}")
    try:
        experiment = mlflow.get_experiment_by_name(mlflow_experiment_name)
        if experiment is None:
            logger.info(f"Experimento '{mlflow_experiment_name}' no encontrado. Creando...")
            mlflow.create_experiment(mlflow_experiment_name)
            logger.info(f"Experimento '{mlflow_experiment_name}' creado.")
        else:
            logger.info(f"Experimento '{mlflow_experiment_name}' ya existe (ID: {experiment.experiment_id}).")
        mlflow.set_experiment(mlflow_experiment_name)
        logger.info(f"Experimento MLflow activo: '{mlflow_experiment_name}'")
    except Exception as e:
        logger.critical(f"Error CRÍTICO configurando experimento MLflow '{mlflow_experiment_name}': {e}. Abortando.")
        sys.exit(1)


    # Carga de Datos
    data_load_start = time.time()
    df = load_data(cfg.get('csv_path'))
    logger.info(f"Carga de datos completada en {time.time() - data_load_start:.2f} seg.")
    if df is None or df.empty: logger.critical("Fallo al cargar datos. Abortando."); sys.exit(1)

    # Preprocesamiento
    preprocess_start = time.time()
    X, y, feature_names_from_preprocess = preprocess(df, cfg) # Usar un nombre diferente para el resultado
    logger.info(f"Preprocesamiento completado en {time.time() - preprocess_start:.2f} seg.")
    # Pasar feature_names_from_preprocess a evaluate_model
    if X is None or y is None or feature_names_from_preprocess is None:
        logger.critical("Fallo en preprocesamiento. Abortando."); sys.exit(1)


    # División Train/Holdout
    split_start = time.time()
    holdout_size = cfg.get('holdout_size', 0.2)
    random_state = cfg.get('random_state')
    X_train_orig, X_holdout, y_train_orig, y_holdout = None, None, None, None
    try:
        min_samples_per_class = np.bincount(y.astype(int)).min()
        # Asegurar que holdout_size sea float
        if isinstance(holdout_size, str):
            try: holdout_size = float(holdout_size)
            except ValueError: raise ValueError(f"holdout_size '{holdout_size}' no es un float válido.")
        if not isinstance(holdout_size, float) or not (0 < holdout_size < 1):
            raise ValueError(f"holdout_size debe ser un float entre 0 y 1, pero es {holdout_size}")

        can_stratify_split = min_samples_per_class >= 2 # Requiere al menos 2 para split estratificado
        if not can_stratify_split: logger.warning(f"No se puede estratificar split (clase minoritaria={min_samples_per_class} < 2). Usando split no estratificado.")

        X_train_orig, X_holdout, y_train_orig, y_holdout = train_test_split(
            X, y, test_size=holdout_size, random_state=random_state, stratify=y if can_stratify_split else None
        )
        logger.info(f"Dividiendo datos: {1-holdout_size:.1%} train, {holdout_size:.1%} holdout (Estratificado: {can_stratify_split})")
        logger.info(f"División completada en {time.time() - split_start:.2f} seg:")
        logger.info(f"  Train Original: X={X_train_orig.shape}, y={y_train_orig.shape}. Clases: {np.bincount(y_train_orig.astype(int))}")
        logger.info(f"  Holdout:        X={X_holdout.shape}, y={y_holdout.shape}. Clases: {np.bincount(y_holdout.astype(int))}")
    except ValueError as e:
        logger.critical(f"Error split (estratificación/tamaño?): {e}.")
        sys.exit(1)
    except Exception as e: logger.critical(f"Error inesperado en split: {e}\n{traceback.format_exc()}"); sys.exit(1)


    # Aplicar SMOTE
    X_train_eval, y_train_eval = X_train_orig.copy(), y_train_orig.copy()
    smote_applied = False
    if cfg.get('use_smote') and IMBLEARN_AVAILABLE and SMOTE is not None:
        smote_start = time.time()
        logger.info("Aplicando SMOTE al conjunto de entrenamiento...")
        sampling_strategy = cfg.get('smote_sampling_strategy', 'auto')
        logger.info(f"Usando SMOTE sampling_strategy: {sampling_strategy}")
        smote_params = {'random_state': random_state, 'sampling_strategy': sampling_strategy}

        # Manejo n_jobs para SMOTE
        smote_n_jobs = cfg.get('n_jobs', 1)
        smote_parallel = False
        if platform.system() == "Windows":
            if smote_n_jobs != 1:
                logger.warning(f"Sistema es Windows. Forzando n_jobs=1 para SMOTE (original n_jobs={smote_n_jobs}).")
                smote_n_jobs = 1
        if smote_n_jobs != 1:
            try: # Intentar usar n_jobs si es posible
                import inspect
                if 'n_jobs' in inspect.signature(SMOTE).parameters:
                    smote_params['n_jobs'] = smote_n_jobs
                    logger.info(f"Intentando instanciar SMOTE con n_jobs={smote_n_jobs}")
                    smote_parallel = True
                else: logger.warning("Versión de SMOTE no acepta 'n_jobs'. Ejecutando secuencialmente.")
            except Exception: logger.warning("No se pudo verificar soporte n_jobs en SMOTE. Ejecutando secuencialmente.")
        else: logger.info("Instanciando SMOTE sin paralelización explícita (n_jobs=1).")

        try: # Instanciar SMOTE
            smote = SMOTE(**smote_params)
        except TypeError as te:
            if 'n_jobs' in str(te) and 'n_jobs' in smote_params: # Fallback si n_jobs falló
                logger.warning(f"TypeError creando SMOTE con n_jobs. Reintentando sin n_jobs.")
                smote_params.pop('n_jobs', None)
                smote = SMOTE(**smote_params)
                smote_parallel = False
            else: raise te # Re-lanzar otro TypeError

        try: # Aplicar SMOTE
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning, module='joblib')
                if X_train_orig is not None and not X_train_orig.empty and y_train_orig is not None and not y_train_orig.empty:
                    X_train_eval, y_train_eval = smote.fit_resample(X_train_orig, y_train_orig)
                    logger.info(f"SMOTE aplicado en {time.time() - smote_start:.2f} seg.")
                    logger.info(f"  Train después de SMOTE: X={X_train_eval.shape}, y={y_train_eval.shape}. Clases: {np.bincount(y_train_eval.astype(int))}")
                    smote_applied = True
                else: logger.error("Datos de entrenamiento originales vacíos antes de SMOTE. SMOTE no aplicado.")
        except Exception as e:
            logger.error(f"Error durante SMOTE fit_resample: {e}. Continuando sin SMOTE.")
            X_train_eval, y_train_eval = X_train_orig, y_train_orig # Revertir
            smote_applied = False
            cfg['use_smote'] = False # Marcar como no aplicado en config
    elif cfg.get('use_smote'): logger.warning("SMOTE activado en config pero librería no disponible o SMOTE=None. Sin SMOTE."); cfg['use_smote'] = False
    else: logger.info("SMOTE no está activado.")


    # Crear Instancia Base del Modelo
    create_model_start = time.time()
    try:
        model_instance = create_model(cfg)
        if model_instance is None: raise ValueError("Creación del modelo retornó None.")
    except Exception as e: logger.critical(f"Error creando instancia modelo: {e}\n{traceback.format_exc()}"); sys.exit(1)
    logger.info(f"Instancia base modelo creada en {time.time() - create_model_start:.2f} seg.")

    # Entrenar y Evaluar (ahora devuelve run_id)
    eval_start = time.time()
    final_trained_model, holdout_metrics_default_thresh, final_run_id = evaluate_model(
        model_instance=model_instance, X_train=X_train_eval, y_train=y_train_eval,
        X_holdout=X_holdout, y_holdout=y_holdout, cfg=cfg,
        feature_names=feature_names_from_preprocess, # Pasar el nombre correcto
        X_train_original=X_train_orig, y_train_original=y_train_orig
    )
    logger.info(f"Fase de Entrenamiento y Evaluación completada en {time.time() - eval_start:.2f} seg.")

    # --- Resumen Final ---
    script_end_time = time.time()
    duration = script_end_time - script_start_time
    logger.info(f"--- Resumen Final del Script ({script_version}) ---")
    model_type_final = cfg.get('model_type', 'N/A').upper()
    status = "Exitoso" if final_trained_model is not None else "Fallido"
    logger.info(f"Estado Final: {status}")
    logger.info(f"Modelo Probado: {model_type_final}")

    # Usar el run_id devuelto por evaluate_model si está disponible
    last_run_id_summary = final_run_id if final_run_id else "N/A (Run no iniciado o fallido)"
    run_data_params = {} # Resetear
    if final_run_id and status == "Exitoso":
        try:
            run_data = mlflow.get_run(run_id=final_run_id).data
            run_data_params = run_data.params
            logger.info(f"Recuperando información del Run ID completado: {final_run_id}")
        except Exception as get_run_err:
            logger.warning(f"Error obteniendo parámetros del run {final_run_id}: {get_run_err}. Resumen puede estar incompleto.")
            last_run_id_summary = f"{final_run_id} (Error recuperando datos)"
    elif status != "Exitoso":
        logger.warning("El entrenamiento no fue exitoso, no se intentará recuperar info detallada del run.")
        if final_run_id: last_run_id_summary = f"{final_run_id} (FALLIDO)"


    # --- Logs del Resumen ---
    # Intentar obtener info de run_data_params o cfg como fallback
    opt_method = run_data_params.get('optimization_method', 'RandomSearch' if cfg.get('use_randomsearch') else 'DirectFit')
    es_configured = cfg.get('early_stopping_rounds') is not None and model_type_final in ('XGB', 'LGBM')
    es_attempted_rs_param = run_data_params.get("early_stopping_in_randomsearch_attempted") == 'True'
    es_attempted_direct_param = run_data_params.get("early_stopping_in_direct_fit_attempted") == 'True'
    gpu_explicit = run_data_params.get('gpu_enabled_explicitly') == 'True' if 'gpu_enabled_explicitly' in run_data_params else (cfg.get('tree_method') == 'gpu_hist' if model_type_final == 'XGB' else cfg.get('device') == 'gpu' if model_type_final == 'LGBM' else False)
    smote_used = run_data_params.get('smote_applied') == 'True' if 'smote_applied' in run_data_params else cfg.get('use_smote', False)

    logger.info(f"Optimización Configurada: {opt_method}" + (f" (n_iter={cfg.get('n_iter')})" if opt_method == 'RandomSearch' else ""))
    logger.info(f"Early Stopping Configurado: {'Sí' if es_configured else 'No'}" + (f" (Rondas={cfg.get('early_stopping_rounds')})" if es_configured else ""))
    if es_configured:
        if opt_method == 'RandomSearch': logger.info(f"  - ES Intentado en RandomizedSearch: {'Sí' if es_attempted_rs_param else 'No/Error/No Aplicable'}")
        elif opt_method == 'DirectFit': logger.info(f"  - ES Intentado en Fit Directo: {'Sí' if es_attempted_direct_param else 'No/Error/No Aplicable'}")
    logger.info(f"SMOTE Configurado/Aplicado: {smote_used}" + (f" (strategy={cfg.get('smote_sampling_strategy', 'auto')})" if smote_used else ""))
    logger.info(f"Uso de GPU Configurado: {'Sí' if gpu_explicit else 'No'}")
    logger.info(f"Paralelización CPU (n_jobs): {cfg.get('n_jobs')}")

    if status == "Exitoso":
        classification_threshold = cfg.get('classification_threshold', 0.5)
        logger.info(f"Métricas Principales en Holdout (umbral={classification_threshold}):")
        if holdout_metrics_default_thresh:
            def format_metric(val): return f"{val:.4f}" if isinstance(val, (float, np.number)) else str(val) if val is not None else 'N/A'
            logger.info(f"  - ROC AUC General: {format_metric(holdout_metrics_default_thresh.get('holdout_roc_auc_overall'))}")
            logger.info(f"  - Accuracy:        {format_metric(holdout_metrics_default_thresh.get('holdout_accuracy'))}")
            logger.info(f"  - F1 Macro:        {format_metric(holdout_metrics_default_thresh.get('holdout_f1_macro'))}")
            logger.info(f"  - Recall Clase 1:  {format_metric(holdout_metrics_default_thresh.get('holdout_recall_1'))}")
            logger.info(f"  - Precision Clase 1:{format_metric(holdout_metrics_default_thresh.get('holdout_precision_1'))}")
            logger.info(f"  - TP / FP (Th={classification_threshold}): {int(holdout_metrics_default_thresh.get('holdout_tp', 0))} / {int(holdout_metrics_default_thresh.get('holdout_fp', 0))}")
        else:
            logger.warning("No se pudieron obtener métricas del holdout para el umbral default (posible error en evaluación).")
        logger.info(f"Consulta MLflow UI para detalles completos (Run ID: {last_run_id_summary}).")
    elif status == "Fallido":
        logger.warning("Proceso finalizado con fallos. Modelo no generado/evaluado correctamente.")
        logger.warning("Revisa logs anteriores para identificar la causa.")
        logger.info(f"Run ID (si se inició): {last_run_id_summary}")


    logger.info(f"Duración total del script: {duration:.2f} segundos")
    logger.info(f"=== Fin del script de entrenamiento ===")


if __name__ == "__main__":
    main()