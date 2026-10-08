"""Programa principal: recibe en vivo el stream pcap de la Raspberry Pi por TCP,
arma ventanas de 2 s, detecta movimiento y publica telemetría para el Dashboard.

Uso: python -m src.main [--usuario NOMBRE] [--verbose]
Sin --usuario, registra para el último usuario que inició sesión en el Dashboard.
"""

import argparse
import getpass
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

RAIZ_PROYECTO = Path(__file__).resolve().parent.parent
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

from src.database.database import (
    TablaSensorInexistente,
    cerrar_eventos_abiertos,
    obtener_usuario_activo,
    obtener_configuracion_usuario,
    verificar_usuario,
)
from src.acciones.notificacion_windows import NotificadorWindows
from src.database.registro_eventos import RegistroEventosAsincrono

# Mismas funciones que usa el parser offline
from src.parser.parser_csi import _calcular_amplitud_fase, _extraer_payload_csi
from src.processing.signal_filter import (
    DESCRIPCION_ESTADO_FILTRO,
    ESTADO_FILTRO_SOS_OK,
    FRECUENCIA_MUESTREO_DEFAULT_HZ,
    FS_MINIMA_CONFIABLE_HZ,
    DetectorMovimiento,
)
from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA, serializar_muestra

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("main")

INTENTOS_LOGIN = 3

HOST = "0.0.0.0"
PORT = 9999

TIMEOUT_INACTIVIDAD_SEG = 30.0

LONGITUD_CABECERA_GLOBAL_PCAP = 24
LONGITUD_CABECERA_PAQUETE_PCAP = 16

LONGITUD_MAXIMA_PAQUETE_RAZONABLE = 65535

MAGIC_NUMBER_US = 0xA1B2C3D4
MAGIC_NUMBER_NS = 0xA1B23C4D

# Ventana deslizante por tiempo real (no por cantidad de paquetes)
DURACION_VENTANA_SEG = 2.0
PASO_DESLIZAMIENTO_SEG = 0.2

MAX_PAQUETES_BUFFER_SEGURIDAD = 50_000

INTERVALO_AVISO_VENTANA_INCOMPLETA_SEG = 5.0

INTERVALO_RESUMEN_SEG = 10.0

INTERVALO_RECORDATORIO_SIN_FILTRO_SEG = 10.0

# Cada cuántas ventanas se relee la configuración (~5 s)
BLOQUES_ENTRE_RELECTURAS_CONFIG = 25

TIMEOUT_ESPERA_RELECTURA_SEG = 3.0

# Sin --usuario: cada cuánto se consulta si alguien inició sesión en el Dashboard
INTERVALO_ESPERA_USUARIO_SEG = 3.0


class ErrorProtocoloPcap(Exception):
    """El stream no respeta el formato pcap."""


def autenticar_usuario(usuario: Optional[str]) -> Optional[Tuple[int, str]]:
    """Pide la contraseña (y el usuario si no se indicó) en la terminal.

    Devuelve (usuario_id, usuario) o None tras INTENTOS_LOGIN intentos fallidos.
    """
    for intento in range(1, INTENTOS_LOGIN + 1):
        nombre = usuario or input("Usuario: ").strip()
        contrasenia = getpass.getpass(f"Contraseña de '{nombre}': ")
        usuario_id = verificar_usuario(nombre, contrasenia)
        if usuario_id is not None:
            logger.info(f"Sesión iniciada como '{nombre}' (usuario_id={usuario_id}).")
            return usuario_id, nombre
        restantes = INTENTOS_LOGIN - intento
        logger.error(
            "Usuario o contraseña incorrectos"
            + (f" (quedan {restantes} intento{'s' if restantes != 1 else ''})." if restantes else ".")
            + " Si el error persiste, verificá que MySQL esté corriendo."
        )
    return None


def cargar_configuracion(usuario_id: int) -> Optional[dict]:
    """Lee la configuración del usuario desde la base."""
    logger.info(f"Cargando configuración del sistema (usuario_id={usuario_id})...")
    config = obtener_configuracion_usuario(usuario_id)

    if config is None:
        logger.error(f"No se encontró configuración para usuario_id={usuario_id}.")
        return None

    logger.info(
        f"Configuración cargada -> umbral_sensibilidad={config['umbral_sensibilidad']}, "
        f"guardar_eventos={config['guardar_eventos']}, enviar_alertas={config['enviar_alertas']}"
    )
    return config


class SesionSensor:
    """Usuario para el que registra el sensor y cambio de usuario pendiente.

    El cambio lo detecta el hilo de relectura, pero se aplica en el hilo que procesa las
    ventanas (aplicar_cambio_pendiente), para no tocar el detector desde dos hilos.
    """

    def __init__(self, usuario_id: int, nombre: str, fijo: bool) -> None:
        self.usuario_id = usuario_id
        self.nombre = nombre
        self.fijo = fijo  # True con --usuario: no sigue al Dashboard
        self.pendiente: Optional[Tuple[int, str, dict]] = None
        self.detector: Optional[DetectorMovimiento] = None
        self.registro: Optional[RegistroEventosAsincrono] = None
        self.notificador: Optional[NotificadorWindows] = None

    def aplicar_config(self, config: dict) -> None:
        self.detector.umbral_sensibilidad = config["umbral_sensibilidad"]
        self.registro.habilitada = config["guardar_eventos"]
        self.notificador.habilitada = config["enviar_alertas"]

    def aplicar_cambio_pendiente(self) -> None:
        pendiente = self.pendiente
        if pendiente is None:
            return
        self.pendiente = None
        usuario_id, nombre, config = pendiente
        # El movimiento en curso queda a nombre del usuario anterior
        self.detector.forzar_fin_evento(motivo="cambio de usuario")
        self.usuario_id, self.nombre = usuario_id, nombre
        self.detector.usuario_id = usuario_id
        self.registro.usuario_id = usuario_id
        self.aplicar_config(config)
        logger.info(
            f"Ahora el sensor registra para '{nombre}' (usuario_id={usuario_id}): "
            f"umbral={config['umbral_sensibilidad']}, guardar eventos="
            f"{'sí' if config['guardar_eventos'] else 'no'}, alertas="
            f"{'sí' if config['enviar_alertas'] else 'no'}."
        )


def _hilo_relectura_configuracion(
    sesion: SesionSensor,
    evento_relectura: threading.Event,
    detener_evento: threading.Event,
) -> None:
    """Relee periódicamente el usuario activo y su configuración, y aplica los cambios."""
    detector, registro_eventos, notificador = sesion.detector, sesion.registro, sesion.notificador
    while not detener_evento.is_set():
        disparado_por_bloques = evento_relectura.wait(timeout=TIMEOUT_ESPERA_RELECTURA_SEG)
        if detener_evento.is_set():
            break
        if disparado_por_bloques:
            evento_relectura.clear()

        if not sesion.fijo:
            try:
                activo = obtener_usuario_activo()
            except TablaSensorInexistente as e:
                logger.error(str(e))
                activo = None
            objetivo = sesion.pendiente[0] if sesion.pendiente else sesion.usuario_id
            if activo is not None and activo["usuario_id"] != objetivo:
                nuevo_id, nuevo_nombre = activo["usuario_id"], activo["username"]
                config_nueva = obtener_configuracion_usuario(nuevo_id)
                if config_nueva is not None:
                    cerrar_eventos_abiertos(nuevo_id)
                    logger.info(
                        f"Se inició sesión en el Dashboard como '{nuevo_nombre}': el sensor "
                        f"cambia de usuario en la próxima ventana."
                    )
                    sesion.pendiente = (nuevo_id, nuevo_nombre, config_nueva)
                continue
        if sesion.pendiente is not None:
            continue  # la configuración nueva se aplica junto con el cambio de usuario

        config = obtener_configuracion_usuario(sesion.usuario_id)
        if config is None:
            logger.warning(
                "Relectura de configuración: no se pudo consultar la BD "
                "(se reintenta en el próximo ciclo)."
            )
            continue

        nuevo_guardar = config["guardar_eventos"]
        if nuevo_guardar != registro_eventos.habilitada:
            logger.info(
                f"Registro de eventos {'ACTIVADO' if nuevo_guardar else 'DESACTIVADO'} "
                f"desde el Dashboard."
            )
            registro_eventos.habilitada = nuevo_guardar

        nuevo_alertas = config["enviar_alertas"]
        if nuevo_alertas != notificador.habilitada:
            logger.info(
                f"Alertas de Windows {'ACTIVADAS' if nuevo_alertas else 'DESACTIVADAS'} "
                f"desde el Dashboard."
            )
            notificador.habilitada = nuevo_alertas

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
    usuario_id: int,
) -> None:
    """Envía por UDP los datos de la ventana al Dashboard."""
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
        usuario_id=usuario_id,
    )
    try:
        sock_telemetria.send(payload)
    except OSError as e:
        logger.debug(f"No se pudo enviar telemetría UDP (se ignora, no es crítico): {e}")


def _recibir_exacto(conexion: socket.socket, n_bytes: int) -> Optional[bytes]:
    """Lee exactamente n_bytes del socket. Devuelve None si se cierra la conexión."""
    buffer = bytearray()
    while len(buffer) < n_bytes:
        fragmento = conexion.recv(n_bytes - len(buffer))
        if not fragmento:
            return None
        buffer.extend(fragmento)
    return bytes(buffer)


def _leer_cabecera_global(conexion: socket.socket) -> Optional[Tuple[str, bool]]:
    """Lee la cabecera global del pcap. Devuelve (orden_bytes, es_nanosegundos) o None."""
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
    """Lee el próximo paquete del stream. Devuelve (datos, timestamp) o None al terminar."""
    cabecera = _recibir_exacto(conexion, LONGITUD_CABECERA_PAQUETE_PCAP)
    if cabecera is None:
        return None

    ts_principal, ts_fraccion, incl_len, _orig_len = struct.unpack(
        f"{orden_bytes}IIII", cabecera
    )

    if not (0 < incl_len <= LONGITUD_MAXIMA_PAQUETE_RAZONABLE):
        raise ErrorProtocoloPcap(
            f"incl_len fuera de rango razonable: {incl_len} bytes."
        )

    datos = _recibir_exacto(conexion, incl_len)
    if datos is None:
        return None

    divisor = 1_000_000_000.0 if es_nanosegundos else 1_000_000.0
    timestamp = ts_principal + (ts_fraccion / divisor)

    return datos, timestamp


def _procesar_paquete_crudo(datos_ethernet: bytes) -> Optional[np.ndarray]:
    """Devuelve el vector de amplitudes de una trama CSI, o None si no lo es."""
    try:
        paquete = Ether(datos_ethernet)
    except Exception as e:
        logger.debug(f"Scapy no pudo reconstruir la trama recibida: {e}")
        return None

    datos_iq = _extraer_payload_csi(paquete)
    if datos_iq is None:
        return None

    amplitud, _fase = _calcular_amplitud_fase(datos_iq)
    if amplitud.size == 0:
        return None

    return amplitud


class ResumenPeriodico:
    """Junta estadísticas de las ventanas e imprime un resumen cada INTERVALO_RESUMEN_SEG."""

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
    sesion: SesionSensor,
    sock_telemetria: socket.socket,
    evento_relectura: threading.Event,
) -> None:
    """Lee los paquetes de una conexión, arma la ventana deslizante y la procesa."""
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

    buffer_ventana: Deque[Tuple[np.ndarray, float]] = deque(maxlen=MAX_PAQUETES_BUFFER_SEGURIDAD)

    n_subportadoras_esperado: Optional[int] = None
    n_paquetes_csi = 0
    n_paquetes_descartados = 0
    n_ventanas_desde_ultima_relectura = 0
    resumen = ResumenPeriodico()

    momento_inicio_espera: float = time.time()
    momento_ultimo_aviso_lento: Optional[float] = None

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
                    f"Tasa de paquetes baja: {len(buffer_ventana)} paquetes CSI en "
                    f"{ahora - momento_inicio_espera:.0f}s sin completar una ventana. "
                    f"Verificá el tráfico iperf3."
                )
                momento_ultimo_aviso_lento = ahora
            continue

        sesion.aplicar_cambio_pendiente()
        resultado, fs_estimada = _procesar_ventana_completa(
            buffer_ventana, sesion.detector, sock_telemetria, n_paquetes_csi, n_paquetes_descartados
        )
        momento_inicio_espera = time.time()
        momento_ultimo_aviso_lento = None

        resumen.registrar(resultado, fs_estimada)
        resumen.emitir_si_corresponde(sesion.detector, resultado["movimiento_detectado"])

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

        n_ventanas_desde_ultima_relectura += 1
        if n_ventanas_desde_ultima_relectura >= BLOQUES_ENTRE_RELECTURAS_CONFIG:
            n_ventanas_desde_ultima_relectura = 0
            evento_relectura.set()

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
    """Calcula la fs real de la ventana, la procesa y envía la telemetría. Devuelve (resultado,
    fs).
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

    _enviar_telemetria(
        sock_telemetria, resultado, fs_estimada, detector.umbral_sensibilidad, detector.usuario_id
    )
    return resultado, fs_estimada


def _obtener_ip_local_probable() -> str:
    """IP de esta PC en la red local (para mostrar el comando de la Raspberry Pi)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "<IP_DE_TU_PC>"


def _imprimir_instrucciones_raspberry_pi() -> None:
    """Muestra el comando a ejecutar en la Raspberry Pi."""
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
    sesion: SesionSensor,
    sock_telemetria: socket.socket,
    evento_relectura: threading.Event,
) -> None:
    """Acepta conexiones de la Raspberry Pi; si una se corta, espera la siguiente."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen(1)

        logger.info(f"Servidor TCP escuchando en {HOST}:{PORT}.")
        _imprimir_instrucciones_raspberry_pi()
        logger.info("Esperando a que la Raspberry Pi se conecte...")

        while True:
            conexion, direccion = servidor.accept()
            conexion.settimeout(TIMEOUT_INACTIVIDAD_SEG)
            logger.info(f"Raspberry Pi conectada desde {direccion[0]}:{direccion[1]}.")

            try:
                _procesar_stream(conexion, sesion, sock_telemetria, evento_relectura)
            except (socket.timeout, TimeoutError):
                logger.warning(
                    f"No llegaron datos en {TIMEOUT_INACTIVIDAD_SEG:.0f}s: se asume que "
                    f"la Raspberry Pi perdió la conexión."
                )
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.warning(f"Conexión con la Raspberry Pi interrumpida: {e}")
            finally:
                # Si se corta el stream durante un movimiento, se cierra el evento
                sesion.detector.forzar_fin_evento()
                conexion.close()
                logger.info("Conexión cerrada. Esperando una nueva conexión...\n")


def _esperar_usuario_activo() -> dict:
    """Espera a que alguien inicie sesión en el Dashboard. Devuelve {usuario_id, username}."""
    avisado = False
    while True:
        activo = obtener_usuario_activo()
        if activo is not None:
            return activo
        if not avisado:
            logger.info("Esperando a que alguien inicie sesión en el Dashboard...")
            avisado = True
        time.sleep(INTERVALO_ESPERA_USUARIO_SEG)


def _parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Orquestador en vivo del sistema de detección de movimiento por CSI Wi-Fi."
    )
    parser.add_argument(
        "-u", "--usuario",
        help="Fija el usuario para el que se registran los movimientos (pide la contraseña). "
             "Si se omite, el sensor registra para quien inicie sesión en el Dashboard.",
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
        logger.setLevel(logging.DEBUG)
        logging.getLogger("signal_filter").setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)

    print("=" * 72)
    print(" SISTEMA DE DETECCIÓN PASIVA DE MOVIMIENTO POR CSI WI-FI")
    print(" Orquestador principal (src/main.py) - MODO EN VIVO (streaming TCP)")
    print("=" * 72)

    if argumentos.usuario:
        autenticado = autenticar_usuario(argumentos.usuario)
        if autenticado is None:
            sys.exit(1)
        sesion = SesionSensor(*autenticado, fijo=True)
    else:
        try:
            activo = _esperar_usuario_activo()
        except TablaSensorInexistente as e:
            logger.error(f"{e} También podés fijar un usuario con --usuario.")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("Cancelado (Ctrl+C).")
            sys.exit(0)
        sesion = SesionSensor(activo["usuario_id"], activo["username"], fijo=False)
        logger.info(
            f"El sensor registra para '{sesion.nombre}', el último usuario que inició sesión en el "
            f"Dashboard. Si entra otro usuario, el sensor cambia solo."
        )
    usuario_id = sesion.usuario_id

    config = cargar_configuracion(usuario_id)
    if config is None:
        sys.exit(1)

    # Eventos que quedaron abiertos en una ejecución anterior
    n_cerrados = cerrar_eventos_abiertos(usuario_id)
    if n_cerrados:
        logger.warning(
            f"Se cerraron {n_cerrados} evento(s) de movimiento que habían quedado abiertos "
            f"en una ejecución anterior (se registran con duración 0)."
        )

    # Acciones que se ejecutan con cada evento de movimiento, cada una en su propio hilo
    registro_eventos = RegistroEventosAsincrono(usuario_id, habilitada=config["guardar_eventos"])
    notificador = NotificadorWindows(habilitada=config["enviar_alertas"])
    acciones = [registro_eventos, notificador]
    for accion in acciones:
        accion.iniciar()

    detector = DetectorMovimiento(
        usuario_id=usuario_id,
        umbral_sensibilidad=config["umbral_sensibilidad"],
        frecuencia_muestreo=FRECUENCIA_MUESTREO_DEFAULT_HZ,
        acciones=acciones,
    )
    sesion.detector, sesion.registro, sesion.notificador = detector, registro_eventos, notificador
    logger.info(
        f"Detector listo: umbral={config['umbral_sensibilidad']}, "
        f"fs mínima={FS_MINIMA_CONFIABLE_HZ:.0f} Hz, "
        f"confirmación={detector.ventanas_confirmacion_entrada}/"
        f"{detector.ventanas_confirmacion_salida} ventanas, "
        f"histéresis={detector.factor_histeresis:.0%}, "
        f"guardar eventos={'sí' if config['guardar_eventos'] else 'no'}, "
        f"alertas={'sí' if config['enviar_alertas'] else 'no'}."
    )

    sock_telemetria = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_telemetria.connect((HOST_TELEMETRIA, PUERTO_TELEMETRIA))
    logger.info(f"Telemetría UDP configurada hacia {HOST_TELEMETRIA}:{PUERTO_TELEMETRIA}.")

    evento_relectura = threading.Event()
    detener_relectura = threading.Event()
    hilo_relectura = threading.Thread(
        target=_hilo_relectura_configuracion,
        args=(sesion, evento_relectura, detener_relectura),
        daemon=True,
        name="relectura-configuracion",
    )
    hilo_relectura.start()

    try:
        _ejecutar_servidor(sesion, sock_telemetria, evento_relectura)
    except KeyboardInterrupt:
        logger.info("Servidor detenido manualmente (Ctrl+C). Cerrando.")
    except OSError as e:
        logger.error(f"No se pudo levantar el servidor TCP en {HOST}:{PORT}: {e}")
        sys.exit(1)
    finally:
        detener_relectura.set()
        detector.forzar_fin_evento()
        for accion in acciones:
            accion.detener()
        sock_telemetria.close()


if __name__ == "__main__":
    main()
