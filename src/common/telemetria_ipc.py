"""
telemetria_ipc.py
==================

Contrato compartido del canal de telemetría en tiempo real entre
`src/main.py` (emisor, ~5 ventanas/seg con ventana deslizante por tiempo)
y `src/ui/dashboard.py` (receptor, pestaña "Telemetría Live").

Por qué UDP sobre loopback (127.0.0.1) y no otra cosa:

    - Los datos son EFÍMEROS por definición: a la interfaz sólo le
      importa la muestra más reciente para graficar en vivo; nadie va a
      querer recuperar "la varianza de hace 3 días" de esto. No tiene
      sentido pagar el costo de un INSERT a disco en MySQL varias veces
      por segundo, las 24 horas, para datos de usar-y-tirar.
    - UDP nunca bloquea al emisor. `send()`/`sendto()` es "fire and
      forget": no hay handshake, no hay ACK, no hay backpressure. Si el
      Dashboard no está corriendo en un momento dado, el datagrama
      simplemente se pierde sin excepción ni demora en `main.py` — que
      es EXACTAMENTE lo que se necesita, porque ese mismo hilo también
      está leyendo en vivo el socket TCP de la Raspberry Pi y no puede
      permitirse quedar bloqueado por la interfaz gráfica ni por un
      instante.
    - El volumen es trivial para UDP: cada datagrama pesa unos 350 bytes
      JSON. Es el mismo patrón que usan sistemas de métricas en
      producción como StatsD: un firehose de telemetría de bajo valor
      individual, donde perder alguna muestra ocasional es aceptable a
      cambio de jamás introducir latencia en el proceso productor.

Validez de cada muestra (`filtro_aplicado` / `estado_filtro`):
    No toda ventana procesada produce una varianza comparable contra el
    umbral. Si la fs real es demasiado baja o la ventana tiene muy pocas
    muestras, el pasabanda SOS no se aplica y la "varianza" resultante
    es la de la señal CRUDA (con DC, deriva lenta y ruido de hardware),
    típicamente órdenes de magnitud mayor que la filtrada. Esos dos
    campos viajan en cada muestra para que el Dashboard pueda distinguir
    "varianza alta por movimiento" de "varianza alta porque la ventana
    no es válida", que es justamente el falso positivo observado con
    tráfico generado por `ping`.

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
    filtro_aplicado: bool,
    estado_filtro: str,
    n_paquetes_ventana: int,
    supera_umbral: bool = False,
    ventanas_sobre_umbral: int = 0,
    ventanas_confirmacion: int = 1,
    umbral_salida: Optional[float] = None,
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

    Args:
        filtro_aplicado: True si la varianza proviene de la señal
            filtrada por el pasabanda SOS; False si el filtro no se pudo
            aplicar y la varianza es de la señal cruda (en ese caso el
            trigger queda inhibido y la muestra NO es comparable contra
            el umbral).
        estado_filtro: código del resultado del filtrado (ver constantes
            `ESTADO_FILTRO_*` en `src/processing/signal_filter.py`), para
            saber POR QUÉ no se filtró.
        n_paquetes_ventana: cantidad de paquetes CSI en la ventana.
        supera_umbral: si ESTA ventana superó el umbral (decisión
            instantánea). `movimiento_detectado`, en cambio, es el estado
            CONFIRMADO tras la racha de ventanas y con histéresis.
        ventanas_sobre_umbral / ventanas_confirmacion: progreso de la
            confirmación (por ejemplo 1 de 3), para que el Dashboard
            muestre "Confirmando 1/3".
        umbral_salida: umbral (más bajo, por histéresis) bajo el cual la
            varianza tiene que quedar para volver a reposo.
    """
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
    }
    return json.dumps(payload).encode("utf-8")


def deserializar_muestra(datos: bytes) -> Optional[dict]:
    """Parsea un datagrama recibido por el Dashboard. Devuelve None si no es válido (se descarta)."""
    try:
        return json.loads(datos.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
