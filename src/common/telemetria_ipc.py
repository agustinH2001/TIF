"""Formato y puerto de la telemetría UDP entre main.py y el Dashboard."""

import json
from typing import Optional

HOST_TELEMETRIA = "127.0.0.1"

PUERTO_TELEMETRIA = 9998


def serializar_muestra(
    varianza_promedio: float,
    fs_estimada: Optional[float],
    umbral_actual: float,
    movimiento_detectado: bool,
    timestamp: float,
    filtro_aplicado: bool,
    estado_filtro: str,
    n_paquetes_ventana: int,
    supera_umbral: bool = False,
    ventanas_sobre_umbral: int = 0,
    ventanas_confirmacion: int = 1,
    umbral_salida: Optional[float] = None,
    usuario_id: Optional[int] = None,
) -> bytes:
    """Arma el datagrama JSON con los datos de una ventana procesada."""
    payload = {
        "varianza_promedio": varianza_promedio,
        "fs_estimada": fs_estimada,
        "umbral_actual": umbral_actual,
        "movimiento_detectado": movimiento_detectado,
        "timestamp": timestamp,
        "filtro_aplicado": filtro_aplicado,
        "estado_filtro": estado_filtro,
        "n_paquetes_ventana": n_paquetes_ventana,
        "supera_umbral": supera_umbral,
        "ventanas_sobre_umbral": ventanas_sobre_umbral,
        "ventanas_confirmacion": ventanas_confirmacion,
        "umbral_salida": umbral_salida,
        "usuario_id": usuario_id,
    }
    return json.dumps(payload).encode("utf-8")


def deserializar_muestra(datos: bytes) -> Optional[dict]:
    """Parsea un datagrama recibido. Devuelve None si no es válido."""
    try:
        return json.loads(datos.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
