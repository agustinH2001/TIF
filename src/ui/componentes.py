"""Componentes y utilidades compartidos por las pantallas."""

import logging
import math
import socket
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk
from PIL import Image

from src.common.telemetria_ipc import deserializar_muestra
from src.ui.tema import COLORES, RADIO_BOTON, RADIO_PANEL, fuente

logger = logging.getLogger("dashboard")

CARPETA_ICONOS = Path(__file__).resolve().parent / "iconos"
DIAS_SEMANA = ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"]
MESES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]

_cache_iconos: dict = {}


def icono(nombre: str, tamanio: int = 20) -> Optional[ctk.CTkImage]:
    """Carga un ícono de src/ui/iconos (None si no existe)."""
    clave = (nombre, tamanio)
    if clave not in _cache_iconos:
        ruta = CARPETA_ICONOS / f"{nombre}.png"
        if not ruta.exists():
            logger.warning(f"No se encontró el ícono {ruta.name}.")
            _cache_iconos[clave] = None
        else:
            imagen = Image.open(ruta)
            _cache_iconos[clave] = ctk.CTkImage(imagen, imagen, size=(tamanio, tamanio))
    return _cache_iconos[clave]


def panel(master, **kwargs) -> ctk.CTkFrame:
    return ctk.CTkFrame(master, fg_color=COLORES["superficie"], corner_radius=RADIO_PANEL, **kwargs)


def boton(master, texto: str, primario: bool = True, **kwargs) -> ctk.CTkButton:
    if primario:
        return ctk.CTkButton(
            master, text=texto, font=fuente(13, True), fg_color=COLORES["boton"],
            hover_color=COLORES["boton_hover"], corner_radius=RADIO_BOTON, height=36, **kwargs,
        )
    return ctk.CTkButton(
        master, text=texto, font=fuente(13), fg_color="transparent", border_width=1,
        border_color=COLORES["linea"], text_color=COLORES["texto"],
        hover_color=COLORES["superficie_alta"], corner_radius=RADIO_BOTON, height=36, **kwargs,
    )


def etiqueta(master, texto: str = "", tamanio: int = 13, negrita: bool = False,
             suave: bool = False, **kwargs) -> ctk.CTkLabel:
    return ctk.CTkLabel(
        master, text=texto, font=fuente(tamanio, negrita),
        text_color=COLORES["texto_suave"] if suave else COLORES["texto"], **kwargs,
    )


def cifra(master, valor: str, descripcion: str, tamanio: int = 22):
    """Valor grande con una descripción debajo. Devuelve (marco, label_valor)."""
    marco = ctk.CTkFrame(master, fg_color="transparent")
    label_valor = etiqueta(marco, valor, tamanio, negrita=True)
    label_valor.pack(anchor="w")
    etiqueta(marco, descripcion, 12, suave=True).pack(anchor="w")
    return marco, label_valor


def en_hilo(widget, funcion: Callable, al_terminar: Callable, *args) -> None:
    """Ejecuta `funcion(*args)` en un hilo y pasa el resultado a `al_terminar` en el hilo de la UI."""
    def trabajo():
        try:
            resultado = funcion(*args)
        except Exception as e:
            logger.error(f"Error en {getattr(funcion, '__name__', 'tarea')}: {e}")
            resultado = None
        try:
            widget.after(0, al_terminar, resultado)
        except RuntimeError:
            pass  # la ventana ya se cerró
    threading.Thread(target=trabajo, daemon=True).start()


def formatear_duracion(segundos: Optional[float]) -> str:
    if segundos is None:
        return "—"
    if segundos < 60:
        return f"{segundos:.1f} s"
    minutos, seg = divmod(int(round(segundos)), 60)
    if minutos < 60:
        return f"{minutos} min {seg:02d} s"
    horas, minutos = divmod(minutos, 60)
    return f"{horas} h {minutos:02d} min"


def formatear_dia(dia: date, corto: bool = False) -> str:
    """'Hoy', 'Ayer' o 'lun 6 oct' ('lun 6' si corto)."""
    hoy = date.today()
    if dia == hoy:
        return "Hoy"
    if (hoy - dia).days == 1:
        return "Ayer"
    texto = f"{DIAS_SEMANA[dia.weekday()]} {dia.day}"
    return texto if corto else f"{texto} {MESES[dia.month - 1]}"


def formatear_umbral(valor: float) -> str:
    if valor >= 100:
        return f"{valor:.0f}"
    if valor >= 1:
        return f"{valor:.2f}"
    return f"{valor:.3f}"


def hace(momento: datetime) -> str:
    """'hace 4 s', 'hace 3 min', 'hace 2 h'."""
    segundos = max((datetime.now() - momento).total_seconds(), 0)
    if segundos < 60:
        return f"hace {segundos:.0f} s"
    if segundos < 3600:
        return f"hace {segundos // 60:.0f} min"
    return f"hace {segundos // 3600:.0f} h"


def escala_log(valor: float, tope: float) -> float:
    """Posición relativa (0 a 1) de un valor en escala logarítmica suave."""
    return min(math.log1p(max(valor, 0) * 3) / math.log1p(tope * 3), 1.0)


class ReceptorTelemetria:
    """Recibe la telemetría UDP de main.py en un hilo aparte y la pasa a un callback."""

    def __init__(self, host: str, port: int, on_muestra) -> None:
        self.host = host
        self.port = port
        self.on_muestra = on_muestra
        self._detener = threading.Event()

    def iniciar(self) -> None:
        threading.Thread(target=self._loop_recepcion, daemon=True).start()

    def detener(self) -> None:
        self._detener.set()

    def _loop_recepcion(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(0.5)
        except OSError as e:
            logger.error(f"No se pudo abrir el puerto de telemetría {self.host}:{self.port}: {e}")
            return

        with sock:
            while not self._detener.is_set():
                try:
                    datos, _ = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                muestra = deserializar_muestra(datos)
                if muestra is not None:
                    self.on_muestra(muestra)
