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
       deslizante y dispara el pipeline de DSP + persistencia
       cada vez que la ventana se llena

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

import logging
import socket
import struct
import sys
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
from src.processing.signal_filter import DetectorMovimiento, FRECUENCIA_MUESTREO_DEFAULT_HZ

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
TAMANO_VENTANA = 200       # paquetes por ventana de análisis DSP
PASO_DESLIZAMIENTO = 20    # paquetes viejos que se descartan tras cada análisis


class ErrorProtocoloPcap(Exception):
    """El stream recibido no respeta el formato pcap esperado (posible desincronización)."""


# ---------------------------------------------------------------------------
# Paso 1: Autenticación y configuración (igual que en la versión anterior)
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


# ---------------------------------------------------------------------------
# Paso 2: Desempaquetado robusto del stream pcap sobre el socket TCP
# ---------------------------------------------------------------------------
def _recibir_exacto(conexion: socket.socket, n_bytes: int) -> Optional[bytes]:
    """
    Lee exactamente `n_bytes` de un socket TCP.

    Los sockets TCP son de flujo continuo: un solo `recv()` puede
    devolver menos bytes de los pedidos (por ejemplo, si el paquete de
    red llegó fragmentado). Por eso hay que iterar hasta completar el
    total solicitado en lugar de confiar en una única llamada.

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

    Args:
        conexion: socket ya conectado, con la cabecera global ya leída.
        orden_bytes: '<' o '>', tal como lo devolvió `_leer_cabecera_global`.
        es_nanosegundos: resolución temporal del campo de timestamp.

    Returns:
        Tupla (bytes_de_la_trama, timestamp_epoch_segundos), o None si
        la conexión se cerró de forma prolija (fin de stream).

    Raises:
        ErrorProtocoloPcap: si `incl_len` da un valor fuera de rango
            razonable, señal de que el stream se desincronizó y ya no
            se puede confiar en el alineamiento de los bytes siguientes.
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
    lugar de recortar bytes de forma estática (por ejemplo `[42:]`), que
    se rompería apenas la cabecera IP tuviera opciones o cualquier campo
    variara en longitud. Scapy disecciona Ethernet/IP/UDP de forma
    correcta sin importar el tamaño real de cada cabecera.

    Reutiliza los mismos extractores internos del parser offline para
    que una trama CSI se procese exactamente igual, venga de un archivo
    .pcap o de este stream en vivo.

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
def _procesar_stream(conexion: socket.socket, detector: DetectorMovimiento) -> None:
    """
    Consume el stream pcap de una conexión ya aceptada: lee la cabecera
    global, y después entra en un loop que arma la ventana deslizante de
    amplitudes y dispara `detector.procesar_ventana()` cada vez que se
    junta un bloque completo de `TAMANO_VENTANA` paquetes CSI válidos.

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
    # El timestamp se usa sólo para estimar la frecuencia de muestreo real
    # de esta ventana (ver más abajo) y comparala con la que asume el filtro.
    buffer_ventana: Deque[Tuple[np.ndarray, float]] = deque(maxlen=TAMANO_VENTANA)

    n_subportadoras_esperado: Optional[int] = None
    n_paquetes_csi = 0
    n_paquetes_descartados = 0

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

        if len(buffer_ventana) == TAMANO_VENTANA:
            _procesar_ventana_completa(buffer_ventana, detector, n_paquetes_csi, n_paquetes_descartados)

            # Ventana deslizante: se descartan los PASO_DESLIZAMIENTO
            # paquetes más viejos en vez de esperar a juntar 200 paquetes
            # nuevos de cero. Así la ventana avanza de a saltos chicos
            # (más resolución temporal) sin tener que correr el filtro
            # Butterworth en CADA paquete que llega (carísimo en tiempo real).
            for _ in range(PASO_DESLIZAMIENTO):
                buffer_ventana.popleft()


def _procesar_ventana_completa(
    buffer_ventana: Deque[Tuple[np.ndarray, float]],
    detector: DetectorMovimiento,
    n_paquetes_csi: int,
    n_paquetes_descartados: int,
) -> None:
    """
    Convierte el buffer circular actual en una matriz de NumPy y la
    envía al motor de DSP (`DetectorMovimiento`), que se encarga de
    filtrar, calcular la varianza, evaluar el trigger, y persistir el
    evento en MySQL si corresponde.
    """
    vectores = [item[0] for item in buffer_ventana]
    timestamps = [item[1] for item in buffer_ventana]

    matriz_ventana = np.array(vectores)

    duracion_ventana_seg = timestamps[-1] - timestamps[0]
    fs_estimada = (
        (len(timestamps) - 1) / duracion_ventana_seg if duracion_ventana_seg > 0 else None
    )

    resultado = detector.procesar_ventana(matriz_ventana)

    estado_legible = "MOVIMIENTO" if resultado["movimiento_detectado"] else "reposo"
    mensaje_fs = (
        f"fs_real≈{fs_estimada:.1f}Hz (asumida={FRECUENCIA_MUESTREO_DEFAULT_HZ}Hz)"
        if fs_estimada is not None
        else "fs_real=N/D"
    )
    logger.info(
        f"[Ventana procesada] estado={estado_legible} | "
        f"varianza={resultado['varianza_promedio']:.4f} | "
        f"evento_nuevo_en_BD={resultado['evento_registrado']} | "
        f"{mensaje_fs} | "
        f"paquetes_csi_totales={n_paquetes_csi} | descartados={n_paquetes_descartados}"
    )

    # Si la fs real se aleja mucho de la asumida por el filtro, el
    # pasabanda de signal_filter.py estaría mirando una banda de
    # frecuencia distinta a la que corresponde. Se avisa para que se
    # pueda ajustar FRECUENCIA_MUESTREO_DEFAULT_HZ en signal_filter.py.
    if fs_estimada is not None and abs(fs_estimada - FRECUENCIA_MUESTREO_DEFAULT_HZ) > (
        0.25 * FRECUENCIA_MUESTREO_DEFAULT_HZ
    ):
        logger.warning(
            f"La frecuencia de muestreo real (~{fs_estimada:.1f} Hz) difiere "
            f"más de un 25% de la asumida en el filtro "
            f"({FRECUENCIA_MUESTREO_DEFAULT_HZ} Hz). Conviene actualizar "
            f"FRECUENCIA_MUESTREO_DEFAULT_HZ en signal_filter.py."
        )


# ---------------------------------------------------------------------------
# Servidor TCP: acepta conexiones y sobrevive a desconexiones de la RPi
# ---------------------------------------------------------------------------
def _obtener_ip_local_probable() -> str:
    """
    Determina la IP de esta PC en la red local, para poder mostrarla en
    las instrucciones de la Raspberry Pi. Usa el truco de "conectar" un
    socket UDP hacia una IP externa sin enviar ningún dato realmente
    (UDP connect() sólo fija el destino por defecto; no transmite nada
    por sí solo), únicamente para que el sistema operativo elija qué
    interfaz de red usaría para llegar hasta ahí.
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


def _ejecutar_servidor(detector: DetectorMovimiento) -> None:
    """
    Levanta el servidor TCP y acepta conexiones en un loop infinito: si
    la Raspberry Pi se desconecta (Wi-Fi caído, tcpdump reiniciado,
    corte de luz, etc.), vuelve a esperar una conexión nueva en lugar de
    terminar el proceso.
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
                _procesar_stream(conexion, detector)
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
def main() -> None:
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
        f"{config['umbral_sensibilidad']} y fs={FRECUENCIA_MUESTREO_DEFAULT_HZ} Hz."
    )

    try:
        _ejecutar_servidor(detector)
    except KeyboardInterrupt:
        logger.info("Servidor detenido manualmente (Ctrl+C). Cerrando.")
    except OSError as e:
        logger.error(f"No se pudo levantar el servidor TCP en {HOST}:{PORT}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
