"""
telemetria_ipc.py
==================

Contrato compartido del canal de telemetría en tiempo real entre
`src/main.py` (emisor, ~32 muestras/seg con la Raspberry Pi real) y
`src/ui/dashboard.py` (receptor, pestaña "Telemetría Live").

Por qué UDP sobre loopback (127.0.0.1) y no otra cosa:

    - Los datos son EFÍMEROS por definición: a la interfaz sólo le
      importa la muestra más reciente para graficar en vivo; nadie va a
      querer recuperar "la varianza de hace 3 días" de esto. No tiene
      sentido pagar el costo de un INSERT a disco en MySQL 32 veces por
      segundo, las 24 horas, para datos de usar-y-tirar.
    - UDP nunca bloquea al emisor. `send()`/`sendto()` es "fire and
      forget": no hay handshake, no hay ACK, no hay backpressure. Si el
      Dashboard no está corriendo en un momento dado, el datagrama
      simplemente se pierde sin excepción ni demora en `main.py` — que
      es EXACTAMENTE lo que se necesita, porque ese mismo hilo también
      está leyendo en vivo el socket TCP de la Raspberry Pi a ~650
      paquetes/seg y no puede permitirse quedar bloqueado por la
      interfaz gráfica ni por un instante.
    - El volumen es trivial para UDP: incluso a 32 muestras/seg, cada
      datagrama pesa unos 150 bytes JSON (~4.8 KB/seg en total sobre
      loopback). Es el mismo patrón que usan sistemas de métricas en
      producción como StatsD: un firehose de telemetría de bajo valor
      individual, donde perder alguna muestra ocasional es aceptable a
      cambio de jamás introducir latencia en el proceso productor.

Este módulo centraliza el puerto y el formato del mensaje para que
emisor y receptor nunca puedan desincronizarse en silencio (por
ejemplo, si mañana se agrega un campo nuevo, se agrega acá una sola vez).
"""

import json
from typing import Optional

HOST_TELEMETRIA = "127.0.0.1"

# Puerto UDP dedicado a telemetría, DISTINTO del puerto 9999 que usa el
# servidor TCP que recibe el stream pcap de la Raspberry Pi.
PUERTO_TELEMETRIA = 9998


def serializar_muestra(
    varianza_promedio: float,
    fs_estimada: Optional[float],
    umbral_actual: float,
    movimiento_detectado: bool,
    timestamp: float,
) -> bytes:
    """
    Arma el payload UDP (JSON) que `main.py` envía en cada ventana
    procesada.

    Se incluye `umbral_actual` junto con cada muestra (no sólo la
    varianza) para que el Dashboard siempre compare contra el umbral
    EXACTO que el orquestador está usando en ese instante para su
    decisión de trigger — evita cualquier desfasaje con la copia que el
    Dashboard pueda tener cacheada de `configuracion_sistema`,
    especialmente justo después de mover el slider.
    """
    payload = {
        "varianza_promedio": varianza_promedio,
        "fs_estimada": fs_estimada,
        "umbral_actual": umbral_actual,
        "movimiento_detectado": movimiento_detectado,
        "timestamp": timestamp,
    }
    return json.dumps(payload).encode("utf-8")


def deserializar_muestra(datos: bytes) -> Optional[dict]:
    """Parsea un datagrama recibido por el Dashboard. Devuelve None si no es válido (se descarta)."""
    try:
        return json.loads(datos.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
