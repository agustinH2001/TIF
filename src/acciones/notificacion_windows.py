"""Acción que avisa cada movimiento con una notificación de Windows y un sonido de alarma."""

import logging
import queue
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger("notificacion_windows")

NOMBRE_APLICACION = "Detector de movimiento CSI"

# Tiempo mínimo entre dos alertas (los eventos más seguidos se registran pero no se avisan)
INTERVALO_MINIMO_ALERTAS_SEG = 5.0

# Sonido de alarma: (frecuencia Hz, duración ms) de cada pitido
PITIDOS_ALARMA = [(1400, 180), (1000, 180), (1400, 180)]

_FIN_DEL_HILO = object()


def _mostrar_toast_winotify(titulo: str, mensaje: str) -> None:
    from winotify import Notification

    # Sin set_audio el toast es silencioso: el sonido lo hace _reproducir_alarma
    toast = Notification(app_id=NOMBRE_APLICACION, title=titulo, msg=mensaje, duration="short")
    toast.show()


def _reproducir_alarma() -> None:
    import winsound

    for frecuencia, duracion_ms in PITIDOS_ALARMA:
        winsound.Beep(frecuencia, duracion_ms)


class NotificadorWindows:
    """Al terminar cada movimiento muestra una notificación con inicio, fin y duración.

    Corre en un hilo propio para no frenar la captura. Si no se puede notificar (otro
    sistema operativo, falta winotify, Windows lo rechaza) lo informa en el log y sigue.
    """

    def __init__(
        self,
        habilitada: bool = True,
        intervalo_minimo_seg: float = INTERVALO_MINIMO_ALERTAS_SEG,
        sonido: bool = True,
        mostrar_toast: Optional[Callable[[str, str], None]] = None,
        reproducir_sonido: Optional[Callable[[], None]] = None,
        reloj: Callable[[], float] = time.monotonic,
    ) -> None:
        self.habilitada = habilitada
        self.intervalo_minimo_seg = intervalo_minimo_seg
        self.sonido = sonido
        self._reloj = reloj
        self._ultima_alerta: Optional[float] = None
        self._cola: "queue.Queue" = queue.Queue(maxsize=50)
        self._hilo: Optional[threading.Thread] = None

        if mostrar_toast is None and reproducir_sonido is None:
            mostrar_toast, reproducir_sonido = self._detectar_backend()
        self._mostrar_toast = mostrar_toast
        self._reproducir_sonido = reproducir_sonido

    @staticmethod
    def _detectar_backend():
        if sys.platform != "win32":
            logger.warning("Las alertas de Windows sólo funcionan en Windows: se informan en el log.")
            return None, None
        try:
            import winotify  # noqa: F401
            toast = _mostrar_toast_winotify
        except ImportError:
            logger.warning("Falta la librería winotify (pip install winotify): alertas sólo con sonido.")
            toast = None
        return toast, _reproducir_alarma

    def iniciar(self) -> None:
        self._hilo = threading.Thread(target=self._procesar_cola, daemon=True, name="alertas")
        self._hilo.start()

    def detener(self, timeout_seg: float = 5.0) -> None:
        if self._hilo is None:
            return
        try:
            self._cola.put(_FIN_DEL_HILO, timeout=timeout_seg)
        except queue.Full:
            return
        self._hilo.join(timeout=timeout_seg)

    def al_iniciar(self, id_evento: int, inicio: datetime, varianza: float) -> None:
        pass

    def al_finalizar(
        self, id_evento: int, inicio: datetime, fin: datetime, duracion: float,
        varianza_maxima: float,
    ) -> None:
        if not self.habilitada:
            return
        ahora = self._reloj()
        if self._ultima_alerta is not None and ahora - self._ultima_alerta < self.intervalo_minimo_seg:
            logger.info(
                f"Alerta omitida: pasaron menos de {self.intervalo_minimo_seg:.0f}s desde la anterior."
            )
            return
        self._ultima_alerta = ahora
        try:
            self._cola.put_nowait((inicio, fin, duracion, varianza_maxima))
        except queue.Full:
            logger.error("Cola de alertas llena: se descarta una alerta.")

    def _procesar_cola(self) -> None:
        while True:
            pedido = self._cola.get()
            if pedido is _FIN_DEL_HILO:
                break
            self._notificar(*pedido)

    def _notificar(self, inicio: datetime, fin: datetime, duracion: float, varianza_maxima: float) -> None:
        titulo = "Movimiento detectado"
        mensaje = (
            f"Inicio {inicio:%H:%M:%S}  ·  Fin {fin:%H:%M:%S}\n"
            f"Duración {duracion:.1f} s  ·  Intensidad {varianza_maxima:.2f}"
        )
        logger.info(f"ALERTA: {titulo}. {mensaje.replace(chr(10), ' | ')}")

        # Primero el toast (no bloquea) y después el sonido (bloquea unos 0.5 s)
        if self._mostrar_toast is not None:
            try:
                self._mostrar_toast(titulo, mensaje)
            except Exception as e:
                logger.warning(f"No se pudo mostrar la notificación de Windows: {e}")
        if self.sonido and self._reproducir_sonido is not None:
            try:
                self._reproducir_sonido()
            except Exception as e:
                logger.warning(f"No se pudo reproducir el sonido de alerta: {e}")
