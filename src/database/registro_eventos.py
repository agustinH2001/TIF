"""
registro_eventos.py
===================

Persistencia ASÍNCRONA de los eventos de movimiento.

Por qué existe:
    `DetectorMovimiento` (signal_filter.py) corre en el mismo hilo que lee
    en vivo el socket TCP de la Raspberry Pi. Si escribiera directamente
    en MySQL, cualquier demora de la base (arranque de XAMPP, un lock, un
    disco lento) frenaría la lectura de paquetes CSI y desordenaría las
    ventanas. Este módulo desacopla las dos cosas: el detector sólo deja
    un pedido en una cola en memoria (operación O(1) que nunca bloquea) y
    un hilo de background dedicado ejecuta los INSERT/UPDATE.

Ciclo de vida de un evento:
    1. `registrar_inicio(...)` cuando el detector confirma el movimiento:
       el hilo de background hace el INSERT y guarda el `evento_id` que
       devuelve MySQL.
    2. `registrar_fin(...)` cuando el movimiento termina: el hilo hace el
       UPDATE sobre ese `evento_id`.

    Como el detector no puede esperar el `evento_id` (lo genera MySQL,
    en el otro hilo), cada evento se identifica con un TOKEN local que
    devuelve `registrar_inicio`. La cola es FIFO y la atiende un único
    hilo, así que el INSERT de un evento siempre se ejecuta antes que su
    UPDATE, y el hilo puede traducir token -> evento_id.

Interfaz común:
    `RegistroEventosAsincrono` (producción) y `RegistroEventosSincrono`
    (pruebas / scripts simples) exponen los mismos métodos, así el
    detector no sabe ni le importa cuál está usando.

Autor: Trabajo Integrador Final - Módulo de Persistencia y Seguridad
"""

import itertools
import logging
import queue
import threading
from datetime import datetime
from typing import Callable, Dict, Optional

logger = logging.getLogger("registro_eventos")

# Tamaño máximo de la cola de escrituras pendientes. Un evento genera dos
# escrituras y los movimientos llegan como mucho cada pocos segundos, así
# que llenarla significa que MySQL está caído hace mucho: en ese caso se
# descarta el pedido (con un ERROR en el log) en lugar de bloquear la
# captura o crecer en memoria sin límite.
TAMANIO_MAXIMO_COLA = 1000

_FIN_DEL_HILO = object()


class RegistroEventosAsincrono:
    """
    Escritor de eventos de movimiento en un hilo de background.

    Uso:
        registro = RegistroEventosAsincrono(usuario_id)
        registro.iniciar()
        token = registro.registrar_inicio(datetime.now(), 1.23)
        ...
        registro.registrar_fin(token, datetime.now(), 2.5, 3.4)
        registro.detener()   # vacía la cola antes de terminar
    """

    def __init__(
        self,
        usuario_id: int,
        funcion_insertar: Optional[Callable] = None,
        funcion_finalizar: Optional[Callable] = None,
    ) -> None:
        """
        Args:
            usuario_id: dueño de los eventos.
            funcion_insertar / funcion_finalizar: inyectables para pruebas;
                por defecto, las funciones reales de `database.py`.
        """
        if funcion_insertar is None or funcion_finalizar is None:
            from src.database.database import (
                finalizar_evento_movimiento,
                insertar_evento_movimiento,
            )

            funcion_insertar = funcion_insertar or insertar_evento_movimiento
            funcion_finalizar = funcion_finalizar or finalizar_evento_movimiento

        self.usuario_id = usuario_id
        self._insertar = funcion_insertar
        self._finalizar = funcion_finalizar
        self._cola: "queue.Queue" = queue.Queue(maxsize=TAMANIO_MAXIMO_COLA)
        self._tokens = itertools.count(1)
        self._id_por_token: Dict[int, Optional[int]] = {}
        self._hilo: Optional[threading.Thread] = None

    # -- Ciclo de vida del hilo -------------------------------------------
    def iniciar(self) -> None:
        self._hilo = threading.Thread(
            target=self._procesar_cola, daemon=True, name="registro-eventos"
        )
        self._hilo.start()

    def detener(self, timeout_seg: float = 5.0) -> None:
        """Termina el hilo DESPUÉS de ejecutar todas las escrituras pendientes."""
        if self._hilo is None:
            return
        try:
            self._cola.put(_FIN_DEL_HILO, timeout=timeout_seg)
        except queue.Full:
            logger.error("Cola de eventos llena al cerrar: se pierden escrituras pendientes.")
            return
        self._hilo.join(timeout=timeout_seg)
        if self._hilo.is_alive():
            logger.warning(
                "El hilo de registro de eventos no terminó a tiempo; "
                "pueden quedar escrituras sin completar."
            )

    # -- Interfaz para el detector (nunca bloquea) ------------------------
    def registrar_inicio(self, timestamp_inicio: datetime, varianza: float) -> int:
        token = next(self._tokens)
        self._encolar(("inicio", token, timestamp_inicio, varianza))
        return token

    def registrar_fin(
        self, token: int, timestamp_fin: datetime, duracion: float, varianza_maxima: float
    ) -> None:
        self._encolar(("fin", token, timestamp_fin, duracion, varianza_maxima))

    def _encolar(self, pedido: tuple) -> None:
        try:
            self._cola.put_nowait(pedido)
        except queue.Full:
            logger.error(
                f"Cola de escrituras de eventos llena ({TAMANIO_MAXIMO_COLA}): se descarta "
                f"un pedido '{pedido[0]}'. ¿Está corriendo MySQL?"
            )

    # -- Hilo de background ------------------------------------------------
    def _procesar_cola(self) -> None:
        while True:
            pedido = self._cola.get()
            if pedido is _FIN_DEL_HILO:
                break
            try:
                self._ejecutar(pedido)
            except Exception as e:  # nunca dejar morir el hilo por un pedido
                logger.error(f"Error inesperado al persistir un evento ({pedido[0]}): {e}")

    def _ejecutar(self, pedido: tuple) -> None:
        tipo, token = pedido[0], pedido[1]
        if tipo == "inicio":
            _, _, timestamp_inicio, varianza = pedido
            evento_id = self._insertar(
                usuario_id=self.usuario_id,
                varianza=varianza,
                duracion=None,
                timestamp_inicio=timestamp_inicio,
            )
            self._id_por_token[token] = evento_id
            if evento_id is None:
                logger.error("No se pudo registrar el inicio de un evento de movimiento.")
        elif tipo == "fin":
            _, _, timestamp_fin, duracion, varianza_maxima = pedido
            evento_id = self._id_por_token.pop(token, None)
            if evento_id is None:
                logger.warning(
                    "Fin de movimiento sin evento registrado en la base (falló el INSERT): "
                    "no se actualiza nada."
                )
                return
            self._finalizar(
                evento_id=evento_id,
                timestamp_fin=timestamp_fin,
                duracion=duracion,
                varianza_maxima=varianza_maxima,
            )


class RegistroEventosSincrono:
    """
    Misma interfaz que `RegistroEventosAsincrono`, pero ejecuta cada
    escritura en el momento, en el hilo que llama. Sólo para pruebas o
    scripts simples: NO usar en el loop en vivo de main.py.
    """

    def __init__(
        self,
        usuario_id: int,
        funcion_insertar: Optional[Callable] = None,
        funcion_finalizar: Optional[Callable] = None,
    ) -> None:
        self._asincrono = RegistroEventosAsincrono(usuario_id, funcion_insertar, funcion_finalizar)

    def iniciar(self) -> None:
        pass

    def detener(self, timeout_seg: float = 5.0) -> None:
        pass

    def registrar_inicio(self, timestamp_inicio: datetime, varianza: float) -> int:
        token = next(self._asincrono._tokens)
        self._asincrono._ejecutar(("inicio", token, timestamp_inicio, varianza))
        return token

    def registrar_fin(
        self, token: int, timestamp_fin: datetime, duracion: float, varianza_maxima: float
    ) -> None:
        self._asincrono._ejecutar(("fin", token, timestamp_fin, duracion, varianza_maxima))
