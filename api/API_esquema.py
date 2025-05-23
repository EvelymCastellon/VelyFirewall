# schemas.py (opcional pero recomendado)
from pydantic import BaseModel

class LogInput(BaseModel):
    imsi: str
    protocolo: str
    operaciones: int
    codigo_error: int
    # Añade todos los campos que usa tu modelo # [cite: 9]