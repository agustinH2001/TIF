"""Acción que guarda los eventos de movimiento en la base, desde un hilo aparte."""

import logging
import queue
import threading
from datetime import datetime
from typing import Callable, Dict, Optional, Set

logger = logging.getLogger("registro_eventos")

TAMANIO_MAXIMO_COLA = 1000

_FIN_DEL_HILO = object()


class RegistroEventosAsincrono:
    """Escribe en la base el inicio y el fin de cada evento, sin frenar la captura.

    `habilitada` corresponde a la opción "Guardar eventos". Se evalúa al inicio de cada
    evento: un evento que ya se empezó a guardar siempre se cierra en la base.
    """

    def __init__(
        self,
        usuario_id: int,
        habilitada: bool = True,
        funcion_insertar: Optional[Callable] = None,
        funcion_finalizar: Optional[Callable] = None,
    ) -> None:
        if funcion_insertar is None or funcion_finalizar is None:
            from src.database.database import (
                finalizar_evento_movimiento,
                insertar_evento_movimiento,
            )

            funcion_insertar = funcion_insertar or insertar_evento_movimiento
            funcion_finalizar = funcion_finalizar or finalizar_evento_movimiento

        self.usuario_id = usuario_id
        self.habilitada = habilitada
        self._insertar = funcion_insertar
        self._finalizar = funcion_finalizar
        self._cola: "queue.Queue" = queue.Queue(maxsize=TAMANIO_MAXIMO_COLA)
        self._eventos_abiertos: Set[int] = set()
        self._id_en_base: Dict[int, Optional[int]] = {}
        self._hilo: Optional[threading.Thread] = None

    def iniciar(self) -> None:
        self._hilo = threading.Thread(
            target=self._procesar_cola, daemon=True, name="registro-eventos"
        )
        self._hilo.start()

    def detener(self, timeout_seg: float = 5.0) -> None:
        """Termina el hilo después de escribir lo que quedó pendiente."""
        if self._hilo is None:
            return
        try:
            self._cola.put(_FIN_DEL_HILO, timeout=timeout_seg)
        except queue.Full:
            logger.error("Cola de eventos llena al cerrar: se pierden escrituras pendientes.")
            return
        self._hilo.join(timeout=timeout_seg)
        if self._hilo.is_alive():
            logger.warning("El registro de eventos no terminó a tiempo.")

    def al_iniciar(self, id_evento: int, inicio: datetime, varianza: float) -> None:
        if not self.habilitada:
            logger.info("Evento no guardado: el registro de eventos está desactivado.")
            return
        self._eventos_abiertos.add(id_evento)
        # El usuario viaja con el pedido: si el sensor cambia de usuario antes de que
        # se escriba, el evento igual queda a nombre de quien estaba activo
        self._encolar(("inicio", id_evento, inicio, varianza, self.usuario_id))

    def al_finalizar(
        self, id_evento: int, inicio: datetime, fin: datetime, duracion: float,
        varianza_maxima: float,
    ) -> None:
        if id_evento not in self._eventos_abiertos:
            return
        self._eventos_abiertos.discard(id_evento)
        self._encolar(("fin", id_evento, fin, duracion, varianza_maxima))

    def _encolar(self, pedido: tuple) -> None:
        try:
            self._cola.put_nowait(pedido)
        except queue.Full:
            logger.error(
                f"Cola de escrituras de eventos llena ({TAMANIO_MAXIMO_COLA}): se descarta "
                f"un pedido '{pedido[0]}'. ¿Está corriendo MySQL?"
            )

    def _procesar_cola(self) -> None:
        while True:
            pedido = self._cola.get()
            if pedido is _FIN_DEL_HILO:
                break
            try:
                self._ejecutar(pedido)
            except Exception as e:
                logger.error(f"Error inesperado al guardar un evento ({pedido[0]}): {e}")

    def _ejecutar(self, pedido: tuple) -> None:
        tipo, id_evento = pedido[0], pedido[1]
        if tipo == "inicio":
            _, _, inicio, varianza, usuario_id = pedido
            id_base = self._insertar(
                usuario_id=usuario_id,
                varianza=varianza,
                duracion=None,
                timestamp_inicio=inicio,
            )
            self._id_en_base[id_evento] = id_base
            if id_base is None:
                logger.error("No se pudo registrar el inicio de un evento de movimiento.")
        elif tipo == "fin":
            _, _, fin, duracion, varianza_maxima = pedido
            id_base = self._id_en_base.pop(id_evento, None)
            if id_base is None:
                logger.warning("Fin de un evento que no se pudo guardar: no se actualiza nada.")
                return
            self._finalizar(
                evento_id=id_base,
                timestamp_fin=fin,
                duracion=duracion,
                varianza_maxima=varianza_maxima,
            )
