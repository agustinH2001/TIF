"""
main.py
=======

Script ejecutable principal del Sistema de Detección Pasiva de Movimiento
por CSI Wi-Fi — MODO EN VIVO (streaming TCP).

Reemplaza a la versión anterior (que generaba ráfagas sintéticas para
validar la lógica de DSP) ahora que el hardware ya captura datos CSI
reales. Este orquestador:

    1. Autentica al usuario y carga su configuración      (BD)
    2. Levanta un servidor TCP que recibe, en vivo, el      (sockets)
       stream pcap que la Raspberry Pi envía por red
    3. Reconstruye cada trama con Scapy y reutiliza los     (parser_csi)
       extractores internos del parser offline
    4. Acumula los vectores de amplitud en una ventana       (signal_filter)
       deslizante, mide la fs REAL de cada ventana a partir
       de los timestamps del propio stream pcap, y dispara
       el pipeline de DSP + persistencia con esa fs (no una
       fs fija asumida de antemano)
    5. Publica telemetría en vivo (varianza, fs real, umbral,  (UDP)
       si la ventana fue filtrada por el SOS y el progreso de la
       confirmación temporal del trigger)
       para que el Dashboard la muestre sin tener que tocar MySQL
    6. Relee el umbral de sensibilidad cada cierta cantidad de   (hilo aparte)
       ventanas procesadas, para enterarse si el usuario lo
       cambió desde el Dashboard mientras el sistema corre

Corrección de bug (fs real vs. fs asumida):
    En la primera versión en vivo, el filtro Butterworth asumía una fs
    fija de 100 Hz. La Raspberry Pi real entrega paquetes CSI a una tasa
    mucho más alta y VARIABLE (~660-690 Hz medidos en pruebas sucesivas,
    según condiciones de captura). La solución no es hardcodear 650 Hz,
    sino medir la fs de CADA ventana a partir de sus propios timestamps y
    pasársela a `DetectorMovimiento.procesar_ventana()` en cada llamada.

Instrumentación del fallback de filtrado:
    Con tráfico escaso (por ejemplo, un `ping` a 1 Hz desde el celular)
    la fs real cae a 2-15 Hz y el pasabanda no se puede aplicar. Antes,
    esa ventana se procesaba igual con la señal CRUDA y su varianza
    (40.000-800.000) disparaba un falso positivo continuo. Ahora el
    detector marca la ventana con `filtro_aplicado=False` y un
    `estado_filtro` que explica el motivo, inhibe el trigger, y este
    orquestador lo reporta en el log (WARNING sólo en las transiciones,
    para no inundar la consola) y en la telemetría UDP.

Cómo llega el stream:
    La Raspberry Pi corre `tcpdump` en modo escritura-a-stdout ("-w -")
    sobre la interfaz en modo monitor con Nexmon CSI activo, y entuba
    esa salida por `netcat` hacia este servidor. El comando EXACTO a
    correr en la Raspberry Pi se imprime en pantalla al arrancar este
    script (ver `_imprimir_instrucciones_raspberry_pi`), porque depende
    de la IP de esta PC en el momento de ejecutar.

    El resultado es, ni más ni menos, un archivo .pcap normal pero
    entregado por un socket en lugar de por disco: primero viaja la
    cabecera global de 24 bytes, y después, para cada paquete
    capturado, una cabecera de registro de 16 bytes (que informa cuántos
    bytes de datos siguen) seguida de esos bytes crudos de la trama.

Requisitos:
    pip install scapy numpy

Ejecución:
    Desde la raíz del proyecto:  python src/main.py
    Como módulo:                 python -m src.main
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Deque, Optional, Tuple

import numpy as np
from scapy.all import Ether

# ---------------------------------------------------------------------------
# Resolución de rutas / imports
# ---------------------------------------------------------------------------
RAIZ_PROYECTO = Path(__file__).resolve().parent.parent
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

from src.database.database import obtener_configuracion_usuario, verificar_usuario

# Nota de arquitectura: `_extraer_payload_csi` y `_calcular_amplitud_fase`
# están marcadas como privadas (prefijo "_") en parser_csi.py porque ahí
# son detalles internos de `extraer_csi()`. Acá las reutilizamos a
# propósito para no duplicar la lógica de filtrado/decodificación de
# Nexmon CSI entre el modo offline (archivo .pcap) y el modo online
# (socket en vivo) — la misma trama, venga de donde venga, se procesa
# exactamente igual. Si este patrón se repite en un tercer lugar,
# convendría promoverlas a funciones públicas de un módulo común.
from src.parser.parser_csi import _calcular_amplitud_fase, _extraer_payload_csi
from src.processing.signal_filter import (
    DESCRIPCION_ESTADO_FILTRO,
    ESTADO_FILTRO_SOS_OK,
    FRECUENCIA_MUESTREO_DEFAULT_HZ,
    FS_MINIMA_CONFIABLE_HZ,
    DetectorMovimiento,
)
from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA, serializar_muestra

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Constantes de sesión / autenticación
# ---------------------------------------------------------------------------
USERNAME_DEMO = "agustin_test"
PASSWORD_DEMO = "Formosa2026!"

# ---------------------------------------------------------------------------
# Constantes del servidor TCP
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 9999

# Si no llega ni un solo byte nuevo en este tiempo, se asume que la
# Raspberry Pi perdió la conexión (se cortó el Wi-Fi, se reinició
# tcpdump, se le fue la luz, etc.) y se vuelve a esperar una conexión
# nueva, en vez de quedar bloqueado esperando para siempre.
TIMEOUT_INACTIVIDAD_SEG = 30.0

# ---------------------------------------------------------------------------
# Constantes del formato de streaming pcap
# ---------------------------------------------------------------------------
LONGITUD_CABECERA_GLOBAL_PCAP = 24
LONGITUD_CABECERA_PAQUETE_PCAP = 16

# Cota superior razonable para el tamaño de un paquete (frame Ethernet).
# Sirve para detectar un stream desincronizado: si "incl_len" da un
# número disparatado, es señal de que dejamos de leer los bytes
# alineados a un registro real, y no hay forma confiable de recuperarse
# más que cerrar la conexión y esperar una nueva.
LONGITUD_MAXIMA_PAQUETE_RAZONABLE = 65535

MAGIC_NUMBER_US = 0xA1B2C3D4  # timestamps con resolución de microsegundos
MAGIC_NUMBER_NS = 0xA1B23C4D  # timestamps con resolución de nanosegundos

# ---------------------------------------------------------------------------
# Constantes de la ventana deslizante
# ---------------------------------------------------------------------------
# IMPORTANTE: la ventana se define por TIEMPO REAL transcurrido, no por
# una cantidad fija de paquetes. En pruebas sucesivas la tasa real de
# paquetes CSI varió de ~2 Hz (ping desde el celular) a ~690 Hz (con
# tráfico activo) — más de dos órdenes de magnitud de diferencia. Por
# eso la ventana se arma acumulando paquetes hasta que el lapso entre el
# primero y el último (medido con sus propios timestamps del pcap)
# alcanza DURACION_VENTANA_SEG, sin importar cuántos paquetes hicieron
# falta para llegar ahí.
DURACION_VENTANA_SEG = 2.0        # duración real de cada ventana de análisis DSP
PASO_DESLIZAMIENTO_SEG = 0.2      # avance real entre ventanas sucesivas

# Techo de seguridad de memoria: por más que la tasa real sea rarísima
# (timestamps corridos, reloj de la RPi desincronizado, etc.), el
# buffer nunca debe crecer sin límite.
MAX_PAQUETES_BUFFER_SEGURIDAD = 50_000

# Si pasan más de este tiempo sin completar una ventana, se informa en
# el log cuántos paquetes se acumularon hasta ahora (a lo sumo una vez
# cada tantos segundos, para no inundar la consola).
INTERVALO_AVISO_VENTANA_INCOMPLETA_SEG = 5.0

# Cada cuánto se imprime el resumen periódico (INFO) en lugar de una línea
# por ventana. El detalle por ventana sigue disponible con --verbose.
INTERVALO_RESUMEN_SEG = 10.0

# Mientras las ventanas sigan sin poder filtrarse, se repite el WARNING
# como recordatorio cada este tiempo (además del aviso en la transición).
INTERVALO_RECORDATORIO_SIN_FILTRO_SEG = 10.0

# ---------------------------------------------------------------------------
# Constantes de la relectura periódica de configuración
# ---------------------------------------------------------------------------
# Con paso de deslizamiento de 0.2s, se procesa una ventana nueva
# aproximadamente cada 200ms (~5 ventanas/seg). Releer MySQL en CADA
# ventana sería un desperdicio (y un riesgo: cualquier consulta corre en
# el hilo que también lee el socket TCP de la Raspberry Pi). En cambio,
# cada BLOQUES_ENTRE_RELECTURAS_CONFIG ventanas se le pide a un hilo de
# background que vuelva a consultar `configuracion_sistema`.
BLOQUES_ENTRE_RELECTURAS_CONFIG = 25  # ≈ cada 5 segundos a ~5 ventanas/seg

# Techo de seguridad: aunque no se junten BLOQUES_ENTRE_RELECTURAS_CONFIG
# ventanas, el hilo de relectura igual revisa la configuración cada tanto.
TIMEOUT_ESPERA_RELECTURA_SEG = 10.0


class ErrorProtocoloPcap(Exception):
    """El stream recibido no respeta el formato pcap esperado (posible desincronización)."""


# ---------------------------------------------------------------------------
# Paso 1: Autenticación y configuración
# ---------------------------------------------------------------------------
def autenticar_usuario() -> Optional[int]:
    """Simula el inicio de sesión invocando la misma verificación que usaría cualquier interfaz real."""
    logger.info(f"Autenticando usuario '{USERNAME_DEMO}'...")
    usuario_id = verificar_usuario(USERNAME_DEMO, PASSWORD_DEMO)

    if usuario_id is None:
        logger.error(
            f"Autenticación fallida para '{USERNAME_DEMO}'. Verificá que XAMPP/MySQL "
            f"esté corriendo y que el usuario exista en csi_db.usuarios."
        )
        return None

    logger.info(f"Autenticación exitosa. usuario_id={usuario_id}")
    return usuario_id


def cargar_configuracion(usuario_id: int) -> Optional[dict]:
    """Recupera umbral_sensibilidad, canal_wifi y bssid_objetivo desde configuracion_sistema."""
    logger.info(f"Cargando configuración del sistema (usuario_id={usuario_id})...")
    config = obtener_configuracion_usuario(usuario_id)

    if config is None:
        logger.error(f"No se encontró configuración para usuario_id={usuario_id}.")
        return None

    logger.info(
        f"Configuración cargada -> umbral_sensibilidad={config['umbral_sensibilidad']}, "
        f"canal_wifi={config['canal_wifi']}, bssid_objetivo={config['bssid_objetivo']}"
    )
    return config


def _hilo_relectura_configuracion(
    usuario_id: int,
    detector: DetectorMovimiento,
    evento_relectura: threading.Event,
    detener_evento: threading.Event,
) -> None:
    """
    Hilo de background dedicado exclusivamente a releer
    `configuracion_sistema` cada vez que el hilo caliente le avisa que
    pasaron `BLOQUES_ENTRE_RELECTURAS_CONFIG` ventanas procesadas —o,
    como máximo, cada `TIMEOUT_ESPERA_RELECTURA_SEG` segundos.

    Corre en su propio hilo a propósito: si esta consulta a MySQL
    tardara, NUNCA debe frenar la lectura de paquetes CSI en vivo.
    Actualiza `detector.umbral_sensibilidad` directamente; una simple
    reasignación de atributo es atómica a nivel de bytecode en
    CPython, así que no hace falta ningún Lock para esto.
    """
    while not detener_evento.is_set():
        disparado_por_bloques = evento_relectura.wait(timeout=TIMEOUT_ESPERA_RELECTURA_SEG)
        if detener_evento.is_set():
            break
        if disparado_por_bloques:
            evento_relectura.clear()

        config = obtener_configuracion_usuario(usuario_id)
        if config is None:
            logger.warning(
                "Relectura de configuración: no se pudo consultar la BD "
                "(se reintenta en el próximo ciclo)."
            )
            continue

        nuevo_umbral = config["umbral_sensibilidad"]
        if nuevo_umbral != detector.umbral_sensibilidad:
            logger.info(
                f"Umbral de sensibilidad actualizado desde el Dashboard: "
                f"{detector.umbral_sensibilidad} -> {nuevo_umbral}"
            )
            detector.umbral_sensibilidad = nuevo_umbral


def _enviar_telemetria(
    sock_telemetria: socket.socket,
    resultado: dict,
    fs_estimada: Optional[float],
    umbral_actual: float,
) -> None:
    """
    Publica la muestra de telemetría de esta ventana hacia el Dashboard
    por UDP (ver `src/common/telemetria_ipc.py`). Es estrictamente "fire
    and forget": si falla, se descarta en silencio (a nivel DEBUG) sin
    afectar al hilo que lee paquetes CSI en vivo.
    """
    payload = serializar_muestra(
        varianza_promedio=resultado["varianza_promedio"],
        fs_estimada=fs_estimada,
        umbral_actual=umbral_actual,
        movimiento_detectado=resultado["movimiento_detectado"],
        timestamp=time.time(),
        filtro_aplicado=resultado["filtro_aplicado"],
        estado_filtro=resultado["estado_filtro"],
        n_paquetes_ventana=resultado["n_paquetes"],
        supera_umbral=resultado["supera_umbral"],
        ventanas_sobre_umbral=resultado["ventanas_sobre_umbral"],
        ventanas_confirmacion=resultado["ventanas_confirmacion"],
        umbral_salida=resultado["umbral_salida"],
    )
    try:
        sock_telemetria.send(payload)
    except OSError as e:
        logger.debug(f"No se pudo enviar telemetría UDP (se ignora, no es crítico): {e}")


# ---------------------------------------------------------------------------
# Paso 2: Desempaquetado robusto del stream pcap sobre el socket TCP
# ---------------------------------------------------------------------------
def _recibir_exacto(conexion: socket.socket, n_bytes: int) -> Optional[bytes]:
    """
    Lee exactamente `n_bytes` de un socket TCP.

    Los sockets TCP son de flujo continuo: un solo `recv()` puede
    devolver menos bytes de los pedidos. Por eso hay que iterar hasta
    completar el total solicitado en lugar de confiar en una única llamada.

    Returns:
        bytes de longitud exacta `n_bytes`, o None si la conexión se
        cerró (recv() devolvió b"") antes de completar la lectura.
    """
    buffer = bytearray()
    while len(buffer) < n_bytes:
        fragmento = conexion.recv(n_bytes - len(buffer))
        if not fragmento:
            return None  # el peer cerró la conexión
        buffer.extend(fragmento)
    return bytes(buffer)


def _leer_cabecera_global(conexion: socket.socket) -> Optional[Tuple[str, bool]]:
    """
    Lee la cabecera global de 24 bytes del stream pcap y determina, a
    partir del "magic number", el orden de bytes (endianness) y la
    resolución temporal (microsegundos o nanosegundos) del resto del
    stream.

    Returns:
        Tupla (orden_bytes, es_nanosegundos), donde orden_bytes es '<'
        (little-endian) o '>' (big-endian). None si la cabecera es
        inválida o la conexión se cerró antes de completarla.
    """
    cabecera = _recibir_exacto(conexion, LONGITUD_CABECERA_GLOBAL_PCAP)
    if cabecera is None:
        return None

    for orden_bytes in ("<", ">"):
        magic = struct.unpack(f"{orden_bytes}I", cabecera[:4])[0]
        if magic == MAGIC_NUMBER_US:
            return orden_bytes, False
        if magic == MAGIC_NUMBER_NS:
            return orden_bytes, True

    logger.error(
        f"Magic number de pcap desconocido ({cabecera[:4].hex()}). "
        f"¿El stream realmente viene de 'tcpdump -w -'?"
    )
    return None


def _recibir_siguiente_paquete(
    conexion: socket.socket, orden_bytes: str, es_nanosegundos: bool
) -> Optional[Tuple[bytes, float]]:
    """
    Lee un registro completo de paquete del stream pcap: la cabecera de
    16 bytes (timestamp + incl_len + orig_len) y, a continuación,
    exactamente `incl_len` bytes de datos crudos de la trama.

    Returns:
        Tupla (bytes_de_la_trama, timestamp_epoch_segundos), o None si
        la conexión se cerró de forma prolija (fin de stream).

    Raises:
        ErrorProtocoloPcap: si `incl_len` da un valor fuera de rango
            razonable (stream desincronizado).
    """
    cabecera = _recibir_exacto(conexion, LONGITUD_CABECERA_PAQUETE_PCAP)
    if cabecera is None:
        return None  # fin de stream prolijo

    ts_principal, ts_fraccion, incl_len, _orig_len = struct.unpack(
        f"{orden_bytes}IIII", cabecera
    )

    if not (0 < incl_len <= LONGITUD_MAXIMA_PAQUETE_RAZONABLE):
        raise ErrorProtocoloPcap(
            f"incl_len fuera de rango razonable: {incl_len} bytes."
        )

    datos = _recibir_exacto(conexion, incl_len)
    if datos is None:
        return None  # se cortó a mitad de un paquete: se trata como fin de stream

    divisor = 1_000_000_000.0 if es_nanosegundos else 1_000_000.0
    timestamp = ts_principal + (ts_fraccion / divisor)

    return datos, timestamp


# ---------------------------------------------------------------------------
# Paso 3: Reconstrucción con Scapy + reutilización del parser interno
# ---------------------------------------------------------------------------
def _procesar_paquete_crudo(datos_ethernet: bytes) -> Optional[np.ndarray]:
    """
    Reconstruye la trama de red con Scapy (`Ether(datos_ethernet)`) en
    lugar de recortar bytes de forma estática, y reutiliza los mismos
    extractores internos del parser offline para que una trama CSI se
    procese exactamente igual, venga de un archivo .pcap o de este
    stream en vivo.

    Returns:
        Vector de amplitud (np.ndarray, una posición por subportadora),
        o None si la trama no es una trama CSI de Nexmon válida.
    """
    try:
        paquete = Ether(datos_ethernet)
    except Exception as e:
        logger.debug(f"Scapy no pudo reconstruir la trama recibida: {e}")
        return None

    datos_iq = _extraer_payload_csi(paquete)
    if datos_iq is None:
        return None  # no era una trama CSI (puerto/MAC no coinciden)

    amplitud, _fase = _calcular_amplitud_fase(datos_iq)
    if amplitud.size == 0:
        return None

    return amplitud


# ---------------------------------------------------------------------------
# Paso 4: Ventana deslizante + disparo del pipeline de DSP
# ---------------------------------------------------------------------------
class ResumenPeriodico:
    """
    Acumula estadísticas de las ventanas procesadas e imprime UNA línea
    de resumen cada `INTERVALO_RESUMEN_SEG` segundos (tiempo de pared),
    en lugar de una línea por ventana (~5 por segundo), que vuelve el log
    ilegible en operación normal.

    Sólo las ventanas filtradas entran en las estadísticas de varianza:
    la varianza de una ventana cruda no es comparable.
    """

    def __init__(self, intervalo_seg: float = INTERVALO_RESUMEN_SEG) -> None:
        self.intervalo_seg = intervalo_seg
        self._reiniciar(time.time())

    def _reiniciar(self, ahora: float) -> None:
        self._inicio = ahora
        self._n_ventanas = 0
        self._n_filtradas = 0
        self._n_sobre_umbral = 0
        self._n_eventos = 0
        self._n_atipicos = 0
        self._varianzas: list = []
        self._fs: list = []

    def registrar(self, resultado: dict, fs_estimada: Optional[float]) -> None:
        self._n_ventanas += 1
        if fs_estimada is not None:
            self._fs.append(fs_estimada)
        if resultado["filtro_aplicado"]:
            self._n_filtradas += 1
            self._varianzas.append(resultado["varianza_promedio"])
            if resultado["supera_umbral"]:
                self._n_sobre_umbral += 1
        if resultado["evento_registrado"]:
            self._n_eventos += 1
        self._n_atipicos += resultado.get("paquetes_atipicos", 0)

    def emitir_si_corresponde(self, detector: DetectorMovimiento, en_movimiento: bool) -> None:
        ahora = time.time()
        if ahora - self._inicio < self.intervalo_seg or self._n_ventanas == 0:
            return

        if self._varianzas:
            v = np.asarray(self._varianzas)
            texto_var = (
                f"varianza mediana={np.median(v):.3f} p95={np.percentile(v, 95):.3f} "
                f"máx={v.max():.3f}"
            )
        else:
            texto_var = "varianza=N/D (ninguna ventana filtrada)"
        texto_fs = f"{np.median(self._fs):.0f}Hz" if self._fs else "N/D"
        pct_filtradas = 100.0 * self._n_filtradas / self._n_ventanas

        logger.info(
            f"[Resumen {ahora - self._inicio:.0f}s] estado={'MOVIMIENTO' if en_movimiento else 'reposo'} | "
            f"ventanas={self._n_ventanas} ({pct_filtradas:.0f}% filtradas) | fs={texto_fs} | "
            f"{texto_var} | umbral={detector.umbral_sensibilidad:.3f} "
            f"(salida {detector.umbral_salida:.3f}) | sobre_umbral={self._n_sobre_umbral} | "
            f"paquetes_atipicos={self._n_atipicos} | eventos_nuevos={self._n_eventos}"
        )
        self._reiniciar(ahora)


def _procesar_stream(
    conexion: socket.socket,
    detector: DetectorMovimiento,
    sock_telemetria: socket.socket,
    evento_relectura: threading.Event,
) -> None:
    """
    Consume el stream pcap de una conexión ya aceptada: lee la cabecera
    global, y después entra en un loop que arma la ventana deslizante de
    amplitudes y dispara `detector.procesar_ventana()` cada vez que el
    lapso entre el primer y el último paquete acumulado alcanza
    `DURACION_VENTANA_SEG` segundos reales.

    Vuelve (return) apenas la conexión se cierra o se detecta un
    problema irrecuperable, dejando que `_ejecutar_servidor` acepte una
    nueva conexión sin caerse.
    """
    resultado_cabecera = _leer_cabecera_global(conexion)
    if resultado_cabecera is None:
        logger.error("No se pudo leer una cabecera global de pcap válida. Cerrando conexión.")
        return

    orden_bytes, es_nanosegundos = resultado_cabecera
    logger.info(
        f"Cabecera global de pcap OK "
        f"(orden de bytes: {'little-endian' if orden_bytes == '<' else 'big-endian'}, "
        f"resolución: {'nanosegundos' if es_nanosegundos else 'microsegundos'})."
    )

    # Cada elemento del buffer es (vector_amplitud, timestamp_del_paquete).
    buffer_ventana: Deque[Tuple[np.ndarray, float]] = deque(maxlen=MAX_PAQUETES_BUFFER_SEGURIDAD)

    n_subportadoras_esperado: Optional[int] = None
    n_paquetes_csi = 0
    n_paquetes_descartados = 0
    n_ventanas_desde_ultima_relectura = 0
    resumen = ResumenPeriodico()

    # Aviso de ventana lenta: se mide cuánto tiempo DE PARED lleva el
    # sistema esperando completar la próxima ventana, y sólo se avisa si
    # esa espera supera INTERVALO_AVISO_VENTANA_INCOMPLETA_SEG. (Antes se
    # avisaba con el primer paquete después de CADA ventana, lo que
    # llenaba el log aunque la tasa fuera perfectamente normal.)
    momento_inicio_espera: float = time.time()
    momento_ultimo_aviso_lento: Optional[float] = None

    # Seguimiento del estado del filtro para avisar sólo en transiciones.
    # Se arranca asumiendo SOS_OK para que la primera ventana inválida
    # genere el WARNING de inmediato.
    ultimo_estado_filtro: str = ESTADO_FILTRO_SOS_OK
    momento_ultimo_recordatorio_sin_filtro: Optional[float] = None
    n_ventanas_sin_filtro_seguidas = 0

    while True:
        try:
            resultado_paquete = _recibir_siguiente_paquete(conexion, orden_bytes, es_nanosegundos)
        except ErrorProtocoloPcap as e:
            logger.error(f"Stream pcap desincronizado ({e}). Cerrando conexión.")
            return

        if resultado_paquete is None:
            logger.info("La Raspberry Pi cerró la conexión (fin del stream).")
            return

        datos_trama, timestamp_paquete = resultado_paquete

        vector_amplitud = _procesar_paquete_crudo(datos_trama)
        if vector_amplitud is None:
            n_paquetes_descartados += 1
            continue

        # Validación de consistencia: todas las ventanas deben tener la
        # misma cantidad de subportadoras para poder apilarse en una
        # matriz rectangular.
        if n_subportadoras_esperado is None:
            n_subportadoras_esperado = vector_amplitud.shape[0]
        elif vector_amplitud.shape[0] != n_subportadoras_esperado:
            logger.warning(
                f"Paquete CSI con {vector_amplitud.shape[0]} subportadoras "
                f"(se esperaban {n_subportadoras_esperado}). Se descarta."
            )
            n_paquetes_descartados += 1
            continue

        n_paquetes_csi += 1
        buffer_ventana.append((vector_amplitud, timestamp_paquete))

        duracion_acumulada = buffer_ventana[-1][1] - buffer_ventana[0][1]

        if duracion_acumulada < DURACION_VENTANA_SEG:
            ahora = time.time()
            espera_larga = (ahora - momento_inicio_espera) >= INTERVALO_AVISO_VENTANA_INCOMPLETA_SEG
            if espera_larga and (
                momento_ultimo_aviso_lento is None
                or (ahora - momento_ultimo_aviso_lento) >= INTERVALO_AVISO_VENTANA_INCOMPLETA_SEG
            ):
                logger.warning(
                    f"Tasa de paquetes baja: hace {ahora - momento_inicio_espera:.0f}s que "
                    f"no se completa una ventana. Acumulando paquetes para completar una ventana de "
                    f"{DURACION_VENTANA_SEG:.1f}s reales: llevamos "
                    f"{len(buffer_ventana)} paquetes CSI válidos "
                    f"({duracion_acumulada:.2f}s de datos reales). Si esto tarda "
                    f"mucho, la tasa real de paquetes es muy baja — generá tráfico "
                    f"controlado desde el dispositivo filtrado por Nexmon (por "
                    f"ejemplo, iperf3 UDP a ~200 paquetes/seg)."
                )
                momento_ultimo_aviso_lento = ahora
            continue

        # Ventana completa (por tiempo real, no por cantidad de paquetes).
        resultado, fs_estimada = _procesar_ventana_completa(
            buffer_ventana, detector, sock_telemetria, n_paquetes_csi, n_paquetes_descartados
        )
        momento_inicio_espera = time.time()
        momento_ultimo_aviso_lento = None

        resumen.registrar(resultado, fs_estimada)
        resumen.emitir_si_corresponde(detector, resultado["movimiento_detectado"])

        # --- Aviso explícito del fallback de filtrado ---------------------
        estado_filtro = resultado["estado_filtro"]
        ahora = time.time()
        if resultado["filtro_aplicado"]:
            if ultimo_estado_filtro != ESTADO_FILTRO_SOS_OK:
                logger.info(
                    f"Filtro SOS restablecido tras {n_ventanas_sin_filtro_seguidas} "
                    f"ventana(s) sin filtrar (fs_real={fs_estimada:.1f}Hz)."
                )
            n_ventanas_sin_filtro_seguidas = 0
            momento_ultimo_recordatorio_sin_filtro = None
        else:
            n_ventanas_sin_filtro_seguidas += 1
            es_transicion = estado_filtro != ultimo_estado_filtro
            toca_recordatorio = (
                momento_ultimo_recordatorio_sin_filtro is None
                or (ahora - momento_ultimo_recordatorio_sin_filtro)
                >= INTERVALO_RECORDATORIO_SIN_FILTRO_SEG
            )
            if es_transicion or toca_recordatorio:
                texto_fs = f"{fs_estimada:.1f}Hz" if fs_estimada is not None else "N/D"
                logger.warning(
                    f"Ventana SIN FILTRAR ({estado_filtro}: "
                    f"{DESCRIPCION_ESTADO_FILTRO.get(estado_filtro, estado_filtro)}) | "
                    f"fs_real={texto_fs} (mínimo {FS_MINIMA_CONFIABLE_HZ:.0f}Hz) | "
                    f"paquetes_en_ventana={resultado['n_paquetes']} | "
                    f"{n_ventanas_sin_filtro_seguidas} ventana(s) seguidas. "
                    f"Trigger inhibido: la varianza cruda no se compara contra el umbral."
                )
                momento_ultimo_recordatorio_sin_filtro = ahora
        ultimo_estado_filtro = estado_filtro

        # Cada BLOQUES_ENTRE_RELECTURAS_CONFIG ventanas, se le avisa al
        # hilo de relectura que vuelva a consultar la BD.
        n_ventanas_desde_ultima_relectura += 1
        if n_ventanas_desde_ultima_relectura >= BLOQUES_ENTRE_RELECTURAS_CONFIG:
            n_ventanas_desde_ultima_relectura = 0
            evento_relectura.set()

        # Ventana deslizante POR TIEMPO: se descartan los paquetes más
        # viejos hasta que la ventana restante mida aproximadamente
        # (DURACION_VENTANA_SEG - PASO_DESLIZAMIENTO_SEG) segundos.
        limite_tiempo = buffer_ventana[-1][1] - (DURACION_VENTANA_SEG - PASO_DESLIZAMIENTO_SEG)
        while len(buffer_ventana) > 1 and buffer_ventana[0][1] < limite_tiempo:
            buffer_ventana.popleft()


def _procesar_ventana_completa(
    buffer_ventana: Deque[Tuple[np.ndarray, float]],
    detector: DetectorMovimiento,
    sock_telemetria: socket.socket,
    n_paquetes_csi: int,
    n_paquetes_descartados: int,
) -> Tuple[dict, Optional[float]]:
    """
    Convierte el buffer actual en una matriz de NumPy, mide la fs real de
    la ventana a partir de los timestamps del propio stream pcap, y se la
    pasa al motor de DSP (`DetectorMovimiento`). Publica además la
    telemetría de esta ventana por UDP.

    Returns:
        Tupla (resultado_del_detector, fs_estimada).
    """
    vectores = [item[0] for item in buffer_ventana]
    timestamps = [item[1] for item in buffer_ventana]

    matriz_ventana = np.array(vectores)

    duracion_ventana_seg = timestamps[-1] - timestamps[0]
    fs_estimada = (
        (len(timestamps) - 1) / duracion_ventana_seg if duracion_ventana_seg > 0 else None
    )

    resultado = detector.procesar_ventana(matriz_ventana, frecuencia_muestreo=fs_estimada)

    if not resultado["filtro_aplicado"]:
        estado_legible = "SIN_FILTRO"
    elif resultado["movimiento_detectado"]:
        estado_legible = "MOVIMIENTO"
    elif resultado["supera_umbral"]:
        estado_legible = (
            f"confirmando {resultado['ventanas_sobre_umbral']}/"
            f"{resultado['ventanas_confirmacion']}"
        )
    else:
        estado_legible = "reposo"

    # Detalle por ventana: sólo con --verbose (nivel DEBUG). En operación
    # normal lo reemplaza el resumen periódico de ResumenPeriodico.
    texto_fs = f"{fs_estimada:.1f}Hz" if fs_estimada is not None else "N/D"
    logger.debug(
        f"[Ventana procesada] estado={estado_legible} | "
        f"filtro={resultado['estado_filtro']} | "
        f"varianza={resultado['varianza_promedio']:.4f} | "
        f"umbral={detector.umbral_sensibilidad:.2f} "
        f"(salida {detector.umbral_salida:.2f}) | "
        f"evento_nuevo_en_BD={resultado['evento_registrado']} | "
        f"atipicos={resultado['paquetes_atipicos']} | "
        f"fs_real={texto_fs} | n_ventana={resultado['n_paquetes']} | "
        f"paquetes_csi_totales={n_paquetes_csi} | descartados={n_paquetes_descartados}"
    )

    _enviar_telemetria(sock_telemetria, resultado, fs_estimada, detector.umbral_sensibilidad)
    return resultado, fs_estimada


# ---------------------------------------------------------------------------
# Servidor TCP: acepta conexiones y sobrevive a desconexiones de la RPi
# ---------------------------------------------------------------------------
def _obtener_ip_local_probable() -> str:
    """
    Determina la IP de esta PC en la red local, para poder mostrarla en
    las instrucciones de la Raspberry Pi. UDP connect() no transmite
    nada: sólo hace que el SO elija la interfaz de salida.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "<IP_DE_TU_PC>"


def _imprimir_instrucciones_raspberry_pi() -> None:
    """Imprime el comando exacto a correr en la Raspberry Pi para iniciar el envío del stream."""
    ip_local = _obtener_ip_local_probable()
    comando = f"sudo tcpdump -i wlan0 -U -w - udp port 5500 | nc {ip_local} {PORT}"

    print("=" * 72)
    print(" COMANDO A CORRER EN LA RASPBERRY PI")
    print("=" * 72)
    print(f"\n  {comando}\n")
    print(
        "  -i wlan0   : interfaz en modo monitor con Nexmon CSI activo\n"
        "               (cambiala si tu interfaz se llama distinto).\n"
        "  -U         : vuelca cada paquete apenas se captura, sin bufferear\n"
        "               por bloques; sin esto, el stream llega demorado y a\n"
        "               las trompadas en vez de en tiempo real.\n"
        "  -w -       : escribe la captura en formato pcap por stdout en vez\n"
        "               de a un archivo.\n"
        f"  nc {ip_local} {PORT} : entuba ese stdout por TCP hacia este servidor.\n"
    )
    print("=" * 72 + "\n")


def _ejecutar_servidor(
    detector: DetectorMovimiento,
    sock_telemetria: socket.socket,
    evento_relectura: threading.Event,
) -> None:
    """
    Levanta el servidor TCP y acepta conexiones en un loop infinito: si
    la Raspberry Pi se desconecta, vuelve a esperar una conexión nueva
    en lugar de terminar el proceso.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen(1)

        logger.info(f"Servidor TCP escuchando en {HOST}:{PORT}.")
        _imprimir_instrucciones_raspberry_pi()
        logger.info("Esperando a que la Raspberry Pi se conecte...")

        while True:  # loop de aceptación: sobrevive a desconexiones individuales
            conexion, direccion = servidor.accept()
            conexion.settimeout(TIMEOUT_INACTIVIDAD_SEG)
            logger.info(f"Raspberry Pi conectada desde {direccion[0]}:{direccion[1]}.")

            try:
                _procesar_stream(conexion, detector, sock_telemetria, evento_relectura)
            except (socket.timeout, TimeoutError):
                logger.warning(
                    f"No llegaron datos en {TIMEOUT_INACTIVIDAD_SEG:.0f}s: se asume que "
                    f"la Raspberry Pi perdió la conexión."
                )
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.warning(f"Conexión con la Raspberry Pi interrumpida: {e}")
            finally:
                conexion.close()
                logger.info("Conexión cerrada. Esperando una nueva conexión...\n")


# ---------------------------------------------------------------------------
# Orquestación principal
# ---------------------------------------------------------------------------
def _parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Orquestador en vivo del sistema de detección de movimiento por CSI Wi-Fi."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Muestra una línea de log por cada ventana procesada (~5 por segundo), "
             "además del resumen periódico. Útil para diagnóstico fino.",
    )
    return parser.parse_args()


def main() -> None:
    argumentos = _parsear_argumentos()
    if argumentos.verbose:
        # Sólo los loggers propios: subir el root a DEBUG traería también
        # el ruido interno de mysql-connector y scapy.
        logger.setLevel(logging.DEBUG)
        logging.getLogger("signal_filter").setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)

    print("=" * 72)
    print(" SISTEMA DE DETECCIÓN PASIVA DE MOVIMIENTO POR CSI WI-FI")
    print(" Orquestador principal (src/main.py) - MODO EN VIVO (streaming TCP)")
    print("=" * 72)

    usuario_id = autenticar_usuario()
    if usuario_id is None:
        sys.exit(1)

    config = cargar_configuracion(usuario_id)
    if config is None:
        sys.exit(1)

    detector = DetectorMovimiento(
        usuario_id=usuario_id,
        umbral_sensibilidad=config["umbral_sensibilidad"],
        frecuencia_muestreo=FRECUENCIA_MUESTREO_DEFAULT_HZ,
    )
    logger.info(
        f"DetectorMovimiento inicializado con umbral_sensibilidad="
        f"{config['umbral_sensibilidad']} (fs de fallback={FRECUENCIA_MUESTREO_DEFAULT_HZ} Hz; "
        f"en vivo se usa la fs REAL de cada ventana; por debajo de "
        f"{FS_MINIMA_CONFIABLE_HZ:.0f} Hz la ventana no se filtra y el trigger se inhibe). "
        f"Confirmación: {detector.ventanas_confirmacion_entrada} ventanas para entrar, "
        f"{detector.ventanas_confirmacion_salida} bajo {detector.factor_histeresis:.0%} "
        f"del umbral para salir."
    )

    # Socket UDP de telemetría hacia el Dashboard. connect() sobre UDP no
    # hace ningún handshake: sólo fija el destino por defecto.
    sock_telemetria = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_telemetria.connect((HOST_TELEMETRIA, PUERTO_TELEMETRIA))
    logger.info(f"Telemetría UDP configurada hacia {HOST_TELEMETRIA}:{PUERTO_TELEMETRIA}.")

    # Hilo de background para la relectura periódica de umbral_sensibilidad.
    evento_relectura = threading.Event()
    detener_relectura = threading.Event()
    hilo_relectura = threading.Thread(
        target=_hilo_relectura_configuracion,
        args=(usuario_id, detector, evento_relectura, detener_relectura),
        daemon=True,
        name="relectura-configuracion",
    )
    hilo_relectura.start()

    try:
        _ejecutar_servidor(detector, sock_telemetria, evento_relectura)
    except KeyboardInterrupt:
        logger.info("Servidor detenido manualmente (Ctrl+C). Cerrando.")
    except OSError as e:
        logger.error(f"No se pudo levantar el servidor TCP en {HOST}:{PORT}: {e}")
        sys.exit(1)
    finally:
        detener_relectura.set()
        sock_telemetria.close()


if __name__ == "__main__":
    main()
