# -*- coding: utf-8 -*-
# cargar_datos_corregido.py — muestra en consola solo lo esencial, solo CSV.

import os
import sys
import logging
import traceback
import pandas as pd
import configparser
from datetime import datetime, timezone

# --- Configuración inicial y Logging ---
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.path.abspath('.')

CONFIG_PATH = os.path.join(BASE_DIR, 'config.ini')
LOG_DIR    = os.path.join(BASE_DIR, 'logs')
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')

for d in (LOG_DIR, REPORT_DIR, OUTPUT_DIR):
    os.makedirs(d, exist_ok=True)

log_file = os.path.join(LOG_DIR, 'data_validation.log')

file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_fmt = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(file_fmt)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.WARNING)
console_fmt = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(console_fmt)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logger.info('--- Iniciando proceso de validación de datos (CSV solamente) ---')

# --- Funciones de validación ---
def validate_imsi(imsi, expected_length: int) -> bool:
    if pd.isna(imsi):
        return False
    if not isinstance(imsi, str):
        if isinstance(imsi, (int, float)) and imsi % 1 == 0:
            imsi = str(int(imsi))
        else:
            imsi = str(imsi)
    return imsi.isdigit() and len(imsi) == expected_length


def validate_timestamp(ts_input, date_format: str = None) -> bool:
    if pd.isna(ts_input):
        return False
    if isinstance(ts_input, (int, float)):
        try:
            datetime.fromtimestamp(int(ts_input), timezone.utc)
            return True
        except Exception:
            return False

    s = str(ts_input)
    if date_format:
        try:
            datetime.strptime(s, date_format)
            return True
        except Exception:
            pass

    common_formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%SZ'
    ]
    for fmt in common_formats:
        try:
            pd.to_datetime(s, format=fmt)
            return True
        except (ValueError, TypeError):
            continue

    try:
        pd.to_datetime(s)
        return True
    except (ValueError, TypeError):
        return False

# --- Carga y validación (solo CSV) ---
def load_and_validate_csv():
    cfg = configparser.ConfigParser()
    if not os.path.exists(CONFIG_PATH):
        logger.critical(f"Falta config.ini en {CONFIG_PATH}")
        print("Error Crítico: no se encontró config.ini.")
        return None

    try:
        cfg.read(CONFIG_PATH, encoding='utf-8')
        csv_rel  = cfg.get('paths', 'csv_path', fallback='').strip()
        if not csv_rel:
            logger.critical("No se especificó 'csv_path' en la sección [paths] de config.ini")
            print("Error Crítico: csv_path no configurado en config.ini.")
            return None

        csv_path = os.path.join(BASE_DIR, csv_rel)

        imsi_col      = cfg.get('validation', 'imsi_column_name', fallback='imsi')
        timestamp_col = cfg.get('validation', 'timestamp_column_name', fallback='timestamp')
        required_cols = [c.strip() for c in cfg.get('validation', 'required_columns', fallback='').split(',') if c.strip()]
        imsi_len      = cfg.getint('validation', 'imsi_length', fallback=15)
        ts_format     = cfg.get('validation', 'timestamp_format', fallback='') or None

        remove_invalid = cfg.getboolean('processing', 'remove_invalid_rows', fallback=True)
        remove_dup     = cfg.getboolean('processing', 'remove_duplicates',   fallback=True)
        dup_list       = [c.strip() for c in cfg.get('processing', 'duplicate_subset_columns', fallback='').split(',') if c.strip()]
        dup_subset     = dup_list if dup_list else None

        logger.info(f"Config CSV cargada: path={csv_path}, required={required_cols}")

    except Exception as e:
        logger.critical(f"Error parseando config.ini: {e}\n{traceback.format_exc()}")
        print(f"Error Crítico al leer config.ini: {e}")
        return None

    if not os.path.exists(csv_path):
        logger.error(f"No existe el archivo CSV: {csv_path}")
        print(f"Error: no existe el archivo CSV: {csv_path}")
        return None

    try:
        try:
            df = pd.read_csv(csv_path, encoding='utf-8')
        except UnicodeDecodeError:
            logger.warning(f"Error decodificación UTF-8 en {csv_rel}, intentando ISO-8859-1")
            df = pd.read_csv(csv_path, encoding='iso-8859-1')

        if df.empty:
            logger.warning(f"El CSV está vacío: {csv_rel}")
            return pd.DataFrame()

        n0, cols = len(df), df.columns.tolist()
        logger.info(f"CSV: {n0} filas, columnas={cols}")

        faltantes = [c for c in required_cols if c not in cols]
        if faltantes:
            logger.error(f"Faltan columnas requeridas en CSV: {faltantes}")
            return pd.DataFrame()

        imsi_ok = df[imsi_col].apply(lambda x: validate_imsi(x, imsi_len)) if imsi_col in cols else pd.Series(True, index=df.index)
        ts_ok   = df[timestamp_col].apply(lambda x: validate_timestamp(x, ts_format)) if timestamp_col in cols else pd.Series(True, index=df.index)

        valid_mask = imsi_ok & ts_ok
        invalid_count = len(valid_mask) - valid_mask.sum()
        if invalid_count:
            logger.warning(f"{invalid_count} filas inválidas detectadas (IMSITimestamp)")

        df_filtered = df[valid_mask] if remove_invalid else df
        n1 = len(df_filtered)
        logger.info(f"Filas tras validación{' y filtrado' if remove_invalid else ''}: {n1}")

        if remove_dup:
            df_final = df_filtered.drop_duplicates(subset=dup_subset, keep='first')
            removed = n1 - len(df_final)
            if removed:
                logger.info(f"{removed} duplicados eliminados{f' en {dup_subset}' if dup_subset else ''}")
        else:
            df_final = df_filtered

        if df_final.empty:
            logger.warning("No quedaron filas válidas tras validación/duplicados.")
            return pd.DataFrame()

        logger.info(f"DataFrame final tiene {len(df_final)} filas.")
        return df_final

    except Exception as e:
        logger.error(f"Error procesando CSV: {e}\n{traceback.format_exc()}")
        return None

# --- Ejecución principal ---
if __name__ == '__main__':
    print('→ Iniciando validación y carga de datos (CSV)...')
    df_result = load_and_validate_csv()

    print('→ Resumen del proceso:')
    if df_result is None:
        print(f"  ❌ Error crítico. Revisa el log: {log_file}")
    elif df_result.empty:
        print('  ⚠️ No se encontraron filas válidas o el CSV está vacío.')
        print('     Revisa `csv_path` en config.ini y el contenido del archivo.')
        print(f'     Consulta el log para más detalles: {log_file}')
    else:
        num_filas = len(df_result)
        print(f"  ✅ Éxito: {num_filas} filas válidas obtenidas.")
        output_file = os.path.join(OUTPUT_DIR, 'combined_valid_data.csv')
        try:
            df_result.to_csv(output_file, index=False, encoding='utf-8-sig')
            print(f"  💾 CSV guardado en: {output_file}")
        except Exception as e:
            print(f"  ❌ Error al guardar CSV: {e}")
            logger.error(f"Error al guardar {output_file}: {e}\n{traceback.format_exc()}")

    print('→ Fin del proceso de carga y validación.')