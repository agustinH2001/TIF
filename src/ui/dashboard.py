"""Interfaz gráfica (CustomTkinter): login, monitoreo, configuración, historial y telemetría.

Las consultas a la base y la recepción UDP corren en hilos aparte; los widgets
se actualizan siempre desde el hilo principal con self.after().
"""

import logging
import math
import socket
import sys
import threading
import tkinter as tk
from collections import deque
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Deque, Optional, Tuple

import customtkinter as ctk

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

from src.database.database import (
    actualizar_configuracion_usuario,
    obtener_configuracion_usuario,
    contar_eventos_usuario,
    obtener_estadisticas_periodo,
    obtener_historico_usuario,
    obtener_resumen_diario,
    obtener_ultimo_evento,
    verificar_usuario,
)
from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA, deserializar_muestra
from src.processing.signal_filter import DESCRIPCION_ESTADO_FILTRO, ESTADO_FILTRO_SOS_OK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("dashboard")


INTERVALO_ACTUALIZACION_MS = 3000

VENTANA_ALERTA_SEGUNDOS = 10

SEGUNDOS_SIN_TELEMETRIA_OFFLINE = 5

DEMORA_CONSULTA_FIN_EVENTO_MS = 700

# Slider en escala logarítmica
UMBRAL_MIN = 0.01
UMBRAL_MAX = 10_000.0
PASOS_SLIDER_UMBRAL = 600

COLOR_ALERTA = "#c0392b"
COLOR_REPOSO = "#27ae60"
COLOR_ERROR = "#e74c3c"
COLOR_EXITO = "#2ecc71"
COLOR_ADVERTENCIA = "#e67e22"
COLOR_SIN_FILTRO = "#5d6d7e"

MAX_MUESTRAS_TELEMETRIA = 150

COLOR_FONDO_GRAFICO = "#1a1a1a"
COLOR_LINEA_UMBRAL = "#f1c40f"
COLOR_LINEA_UMBRAL_SALIDA = "#8e7a1f"
COLOR_CANDIDATA = "#e67e22"

# Historial
COLOR_BARRA_HISTORIAL = "#3b8ed0"
COLOR_GRILLA = "#333333"
COLOR_TEXTO_EJE = "#9a9a9a"
COLOR_TEXTO_DATO = "#e6e6e6"
EVENTOS_POR_PAGINA = 10
# Período -> cantidad de días (None = sin límite)
PERIODOS_HISTORIAL = {"Hoy": 1, "7 días": 7, "30 días": 30, "Todo": None}


def _umbral_a_posicion_slider(umbral: float) -> float:
    """Convierte un umbral a la posición (log10) del slider."""
    umbral = min(max(float(umbral), UMBRAL_MIN), UMBRAL_MAX)
    return math.log10(umbral)


def _posicion_slider_a_umbral(posicion: float) -> float:
    """Convierte la posición del slider a un umbral redondeado."""
    valor = 10 ** float(posicion)
    if valor >= 100:
        return float(round(valor))
    if valor >= 10:
        return round(valor, 1)
    if valor >= 1:
        return round(valor, 2)
    return round(valor, 3)


def _formatear_duracion(segundos: Optional[float]) -> str:
    """Duración legible: '3.2 s', '4 min 05 s' o '1 h 12 min'."""
    if segundos is None:
        return "—"
    if segundos < 60:
        return f"{segundos:.1f} s"
    minutos, seg = divmod(int(round(segundos)), 60)
    if minutos < 60:
        return f"{minutos} min {seg:02d} s"
    horas, minutos = divmod(minutos, 60)
    return f"{horas} h {minutos:02d} min"


def _formatear_umbral(valor: float) -> str:
    """Texto del umbral con decimales según su magnitud."""
    if valor >= 100:
        return f"{valor:.0f}"
    if valor >= 1:
        return f"{valor:.2f}"
    return f"{valor:.3f}"


class FrameLogin(ctk.CTkFrame):
    """Pantalla de inicio de sesión."""

    def __init__(self, master: "DashboardApp", on_login_exitoso):
        super().__init__(master, fg_color="transparent")
        self.on_login_exitoso = on_login_exitoso

        contenedor = ctk.CTkFrame(self, corner_radius=16, width=380)
        contenedor.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            contenedor,
            text="CSI Motion Detector",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, padx=40, pady=(30, 5))

        ctk.CTkLabel(
            contenedor,
            text="Iniciá sesión para ver el estado del canal",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        ).grid(row=1, column=0, padx=40, pady=(0, 20))

        self.entry_usuario = ctk.CTkEntry(contenedor, placeholder_text="Usuario", width=260)
        self.entry_usuario.grid(row=2, column=0, padx=40, pady=8)

        self.entry_password = ctk.CTkEntry(
            contenedor, placeholder_text="Contraseña", show="*", width=260
        )
        self.entry_password.grid(row=3, column=0, padx=40, pady=8)
        self.entry_password.bind("<Return>", lambda _evento: self._intentar_login())

        self.label_error = ctk.CTkLabel(contenedor, text="", text_color=COLOR_ERROR)
        self.label_error.grid(row=4, column=0, padx=40, pady=(4, 0))

        self.boton_login = ctk.CTkButton(
            contenedor, text="Ingresar", width=260, command=self._intentar_login
        )
        self.boton_login.grid(row=5, column=0, padx=40, pady=(16, 30))

    def _intentar_login(self) -> None:
        username = self.entry_usuario.get().strip()
        password = self.entry_password.get()

        if not username or not password:
            self.label_error.configure(text="Completá usuario y contraseña.")
            return

        self.boton_login.configure(state="disabled", text="Verificando...")
        self.label_error.configure(text="")

        hilo = threading.Thread(
            target=self._verificar_en_hilo, args=(username, password), daemon=True
        )
        hilo.start()

    def _verificar_en_hilo(self, username: str, password: str) -> None:
        try:
            usuario_id = verificar_usuario(username, password)
        except Exception as e:
            usuario_id = None
            logger.error(f"Error inesperado al verificar usuario: {e}")

        self.after(0, self._procesar_resultado, usuario_id, username)

    def _procesar_resultado(self, usuario_id: Optional[int], username: str) -> None:
        self.boton_login.configure(state="normal", text="Ingresar")

        if usuario_id is None:
            self.label_error.configure(text="Usuario o contraseña incorrectos.")
            return

        self.on_login_exitoso(usuario_id, username)


class PanelMonitoreo(ctk.CTkFrame):
    """Tarjeta de estado: usa la telemetría en vivo para la alerta y la base
    de datos para los detalles del último evento.
    """

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self._detenido = False

        self._momento_ultima_muestra: Optional[datetime] = None
        self._fs_ultima_muestra: Optional[float] = None
        self._movimiento_vivo: bool = False
        self._inicio_vivo: Optional[datetime] = None
        self._fin_vivo: Optional[datetime] = None
        self._ultimo_evento: Optional[dict] = None

        self.grid_columnconfigure(0, weight=1)

        self.tarjeta = ctk.CTkFrame(self, corner_radius=20, fg_color=COLOR_SIN_FILTRO, height=220)
        self.tarjeta.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        self.tarjeta.grid_propagate(False)

        self.label_estado = ctk.CTkLabel(
            self.tarjeta,
            text="Verificando estado del canal...",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="white",
        )
        self.label_estado.place(relx=0.5, rely=0.40, anchor="center")

        self.label_detalle = ctk.CTkLabel(
            self.tarjeta,
            text="",
            font=ctk.CTkFont(size=14),
            text_color="white",
        )
        self.label_detalle.place(relx=0.5, rely=0.62, anchor="center")

        self.label_sensor = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.label_sensor.grid(row=1, column=0, pady=(0, 10))

        self._programar_actualizacion(inmediato=True)

    def recibir_muestra(self, muestra: dict) -> None:
        estaba_en_linea = self._sensor_en_linea()
        ahora = datetime.now()
        self._momento_ultima_muestra = ahora
        self._fs_ultima_muestra = muestra.get("fs_estimada")
        movimiento = bool(muestra.get("movimiento_detectado", False))

        if movimiento != self._movimiento_vivo:
            if movimiento:
                self._inicio_vivo, self._fin_vivo = ahora, None
            else:
                self._fin_vivo = ahora
                # Consulta puntual para mostrar la duración real del evento que terminó
                self.after(DEMORA_CONSULTA_FIN_EVENTO_MS, self._disparar_consulta, False)
            self._movimiento_vivo = movimiento
            self._renderizar()
        elif not estaba_en_linea:
            self._renderizar()

    def _programar_actualizacion(self, inmediato: bool = False) -> None:
        if self._detenido:
            return
        demora = 0 if inmediato else INTERVALO_ACTUALIZACION_MS
        self.after(demora, self._disparar_consulta)

    def _disparar_consulta(self, reprogramar: bool = True) -> None:
        """Consulta el último evento en un hilo aparte (reprogramar=False para consultas
        puntuales).
        """
        if self._detenido:
            return
        hilo = threading.Thread(target=self._consultar_en_hilo, args=(reprogramar,), daemon=True)
        hilo.start()

    def _consultar_en_hilo(self, reprogramar: bool) -> None:
        try:
            ultimo_evento = obtener_ultimo_evento(self.usuario_id)
        except Exception as e:
            ultimo_evento = None
            logger.error(f"Error al consultar el último evento de movimiento: {e}")

        self.after(0, self._recibir_evento_db, ultimo_evento, reprogramar)

    def _recibir_evento_db(self, ultimo_evento: Optional[dict], reprogramar: bool) -> None:
        if self._detenido:
            return
        self._ultimo_evento = ultimo_evento
        self._renderizar()
        if reprogramar:
            self._programar_actualizacion()

    def _sensor_en_linea(self) -> bool:
        return (
            self._momento_ultima_muestra is not None
            and (datetime.now() - self._momento_ultima_muestra).total_seconds()
            <= SEGUNDOS_SIN_TELEMETRIA_OFFLINE
        )

    def _renderizar(self) -> None:
        ahora = datetime.now()
        evento = self._ultimo_evento
        en_linea = self._sensor_en_linea()

        evento_reciente = None
        if evento is not None:
            fin = evento.get("timestamp_fin")
            if fin is None or (ahora - fin).total_seconds() <= VENTANA_ALERTA_SEGUNDOS:
                evento_reciente = evento

        if en_linea and self._movimiento_vivo:
            inicio = (evento_reciente or {}).get("timestamp") or self._inicio_vivo or ahora
            transcurrido = max((ahora - inicio).total_seconds(), 0)
            self._pintar(
                COLOR_ALERTA,
                "¡MOVIMIENTO EN CURSO!",
                f"Desde las {inicio:%H:%M:%S} ({transcurrido:.0f}s)",
            )
        elif evento_reciente is not None and evento_reciente.get("timestamp_fin") is not None:
            duracion = evento_reciente.get("duracion_segundos") or 0.0
            intensidad = evento_reciente.get("varianza_maxima") or 0.0
            self._pintar(
                COLOR_ALERTA,
                "¡MOVIMIENTO DETECTADO!",
                f"Hora: {evento_reciente['timestamp']:%H:%M:%S}   |   Duración: {duracion:.1f}s"
                f"   |   Intensidad pico: {intensidad:.2f}",
            )
        elif (
            self._fin_vivo is not None
            and (ahora - self._fin_vivo).total_seconds() <= VENTANA_ALERTA_SEGUNDOS
        ):
            self._pintar(
                COLOR_ALERTA,
                "¡MOVIMIENTO DETECTADO!",
                f"Terminó a las {self._fin_vivo:%H:%M:%S}",
            )
        elif not en_linea:
            self._pintar(
                COLOR_SIN_FILTRO,
                "Sensor sin datos",
                "No llega telemetría de main.py: verificá el proceso y la captura de la Raspberry Pi.",
            )
        else:
            if evento is None:
                detalle = "Todavía no hay movimientos en el historial."
            else:
                momento = evento.get("timestamp_fin") or evento["timestamp"]
                formato = "%H:%M:%S" if momento.date() == ahora.date() else "%d/%m %H:%M"
                detalle = f"Último movimiento guardado: {momento.strftime(formato)}"
            self._pintar(COLOR_REPOSO, "Entorno Seguro / En Reposo", detalle)

        if en_linea:
            fs = self._fs_ultima_muestra
            texto_fs = f" · {fs:.0f} Hz" if fs else ""
            self.label_sensor.configure(text=f"Sensor: en línea{texto_fs}   ·   Actualizado {ahora:%H:%M:%S}")
        else:
            self.label_sensor.configure(text=f"Sensor: sin datos   ·   Actualizado {ahora:%H:%M:%S}")

    def _pintar(self, color: str, titulo: str, detalle: str) -> None:
        self.tarjeta.configure(fg_color=color)
        self.label_estado.configure(text=titulo)
        self.label_detalle.configure(text=detalle)

    def detener(self) -> None:
        self._detenido = True


class PanelConfiguracion(ctk.CTkFrame):
    """Umbral de sensibilidad y opciones de guardar eventos y enviar alertas."""

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self._config_actual: Optional[dict] = None

        self.grid_columnconfigure(0, weight=1)

        panel = ctk.CTkFrame(self, corner_radius=16)
        panel.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            panel, text="Configuración del sistema",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=24, pady=(20, 16))

        ctk.CTkLabel(
            panel, text="Umbral de sensibilidad (varianza mínima para disparar una alerta):",
        ).grid(row=3, column=0, sticky="w", padx=24, pady=(4, 2))

        fila_slider = ctk.CTkFrame(panel, fg_color="transparent")
        fila_slider.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 4))
        fila_slider.grid_columnconfigure(0, weight=1)

        self.slider_umbral = ctk.CTkSlider(
            fila_slider,
            from_=math.log10(UMBRAL_MIN),
            to=math.log10(UMBRAL_MAX),
            number_of_steps=PASOS_SLIDER_UMBRAL,
            command=self._on_slider_cambia,
        )
        self.slider_umbral.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.slider_umbral.set(_umbral_a_posicion_slider(UMBRAL_MIN))

        self.label_umbral_valor = ctk.CTkLabel(fila_slider, text="—", width=60)
        self.label_umbral_valor.grid(row=0, column=1)

        ctk.CTkLabel(
            panel,
            text=(
                f"Escala logarítmica ({_formatear_umbral(UMBRAL_MIN)} a "
                f"{_formatear_umbral(UMBRAL_MAX)}). Calibrá ubicándolo entre la varianza "
                f"en reposo y la varianza con movimiento (ver Telemetría Live)."
            ),
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=5, column=0, sticky="w", padx=24, pady=(0, 16))

        self.switch_guardar_eventos = ctk.CTkSwitch(
            panel, text="Guardar los eventos de movimiento en el historial"
        )
        self.switch_guardar_eventos.grid(row=6, column=0, sticky="w", padx=24, pady=(4, 2))
        self.switch_guardar_eventos.select()

        ctk.CTkLabel(
            panel,
            text=(
                "Desactivado, el sistema sigue detectando y alertando en vivo, pero no "
                "guarda nada en la base de datos."
            ),
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=7, column=0, sticky="w", padx=24, pady=(0, 8))

        self.switch_enviar_alertas = ctk.CTkSwitch(
            panel, text="Enviar alertas de Windows (notificación y sonido)"
        )
        self.switch_enviar_alertas.grid(row=8, column=0, sticky="w", padx=24, pady=(8, 2))
        self.switch_enviar_alertas.select()

        ctk.CTkLabel(
            panel,
            text="Una alerta al terminar cada movimiento, con su inicio, fin y duración.",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=9, column=0, sticky="w", padx=24, pady=(0, 8))

        self.boton_guardar = ctk.CTkButton(
            panel, text="Guardar cambios", command=self._guardar_cambios
        )
        self.boton_guardar.grid(row=10, column=0, sticky="w", padx=24, pady=(16, 4))

        self.label_estado_guardado = ctk.CTkLabel(panel, text="", text_color="gray")
        self.label_estado_guardado.grid(row=11, column=0, sticky="w", padx=24, pady=(0, 20))

        self._cargar_configuracion()

    def _cargar_configuracion(self) -> None:
        self.label_estado_guardado.configure(text="Cargando configuración...", text_color="gray")
        hilo = threading.Thread(target=self._cargar_en_hilo, daemon=True)
        hilo.start()

    def _cargar_en_hilo(self) -> None:
        try:
            config = obtener_configuracion_usuario(self.usuario_id)
        except Exception as e:
            config = None
            logger.error(f"Error al cargar configuración: {e}")

        self.after(0, self._mostrar_configuracion, config)

    def _mostrar_configuracion(self, config: Optional[dict]) -> None:
        if config is None:
            self.label_estado_guardado.configure(
                text="No se pudo cargar la configuración.", text_color=COLOR_ERROR
            )
            return

        self._config_actual = config
        umbral_guardado = float(config["umbral_sensibilidad"])
        self.slider_umbral.set(_umbral_a_posicion_slider(umbral_guardado))
        self.label_umbral_valor.configure(text=_formatear_umbral(umbral_guardado))
        for switch, clave in (
            (self.switch_guardar_eventos, "guardar_eventos"),
            (self.switch_enviar_alertas, "enviar_alertas"),
        ):
            if config.get(clave, True):
                switch.select()
            else:
                switch.deselect()
        self.label_estado_guardado.configure(text="")

    def _on_slider_cambia(self, posicion: float) -> None:
        self.label_umbral_valor.configure(
            text=_formatear_umbral(_posicion_slider_a_umbral(posicion))
        )

    def _guardar_cambios(self) -> None:
        if self._config_actual is None:
            self.label_estado_guardado.configure(
                text="Todavía no se cargó la configuración actual.", text_color=COLOR_ERROR
            )
            return

        nuevo_umbral = _posicion_slider_a_umbral(self.slider_umbral.get())
        guardar_eventos = bool(self.switch_guardar_eventos.get())
        enviar_alertas = bool(self.switch_enviar_alertas.get())

        self.boton_guardar.configure(state="disabled", text="Guardando...")
        self.label_estado_guardado.configure(text="")

        hilo = threading.Thread(
            target=self._guardar_en_hilo,
            args=(nuevo_umbral, guardar_eventos, enviar_alertas),
            daemon=True,
        )
        hilo.start()

    def _guardar_en_hilo(
        self, umbral: float, guardar_eventos: bool, enviar_alertas: bool
    ) -> None:
        try:
            exito = actualizar_configuracion_usuario(
                self.usuario_id, umbral,
                guardar_eventos=guardar_eventos, enviar_alertas=enviar_alertas,
            )
        except Exception as e:
            exito = False
            logger.error(f"Error al guardar configuración: {e}")

        self.after(
            0, self._procesar_resultado_guardado, exito, umbral, guardar_eventos, enviar_alertas
        )

    def _procesar_resultado_guardado(
        self, exito: bool, umbral_guardado: float, guardar_eventos: bool, enviar_alertas: bool
    ) -> None:
        self.boton_guardar.configure(state="normal", text="Guardar cambios")

        if exito:
            self._config_actual["umbral_sensibilidad"] = umbral_guardado
            self._config_actual["guardar_eventos"] = guardar_eventos
            self._config_actual["enviar_alertas"] = enviar_alertas
            self.label_estado_guardado.configure(
                text=(
                    "✔ Configuración guardada. main.py la aplica en unos segundos."
                ),
                text_color=COLOR_EXITO,
            )
        else:
            self.label_estado_guardado.configure(
                text="✘ No se pudo guardar la configuración.", text_color=COLOR_ERROR
            )


class ReceptorTelemetria:
    """Recibe la telemetría UDP en un hilo aparte y la pasa a un callback."""

    def __init__(self, host: str, port: int, on_muestra) -> None:
        self.host = host
        self.port = port
        self.on_muestra = on_muestra
        self._detener = threading.Event()
        self._hilo: Optional[threading.Thread] = None

    def iniciar(self) -> None:
        self._hilo = threading.Thread(target=self._loop_recepcion, daemon=True)
        self._hilo.start()

    def detener(self) -> None:
        self._detener.set()

    def _loop_recepcion(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(0.5)
        except OSError as e:
            logger.error(
                f"No se pudo abrir el socket UDP de telemetría en "
                f"{self.host}:{self.port}: {e}. La pestaña de Telemetría "
                f"Live no va a recibir datos."
            )
            return

        with sock:
            while not self._detener.is_set():
                try:
                    datos, _direccion = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                muestra = deserializar_muestra(datos)
                if muestra is not None and self.on_muestra is not None:
                    self.on_muestra(muestra)


class PanelTelemetria(ctk.CTkFrame):
    """Lecturas en vivo y gráfico de varianza contra el umbral."""

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id

        self.historial: Deque[Tuple[float, bool]] = deque(maxlen=MAX_MUESTRAS_TELEMETRIA)
        self.umbral_actual: float = 0.0
        self.umbral_salida: Optional[float] = None
        self._ultima_muestra_recibida = False

        self.grid_columnconfigure(0, weight=1)

        fila_lecturas = ctk.CTkFrame(self, corner_radius=16)
        fila_lecturas.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 4))
        for col in range(5):
            fila_lecturas.grid_columnconfigure(col, weight=1)

        _, self.valor_estado = self._crear_lectura(fila_lecturas, 0, "Estado")
        _, self.valor_filtro = self._crear_lectura(fila_lecturas, 1, "Filtro")
        _, self.valor_varianza = self._crear_lectura(fila_lecturas, 2, "Varianza instantánea")
        _, self.valor_umbral = self._crear_lectura(
            fila_lecturas, 3, "Umbral entrada / salida"
        )
        _, self.valor_fs = self._crear_lectura(fila_lecturas, 4, "Frecuencia real")

        self.valor_estado.configure(text="Sin datos")
        for label in (self.valor_filtro, self.valor_varianza, self.valor_umbral, self.valor_fs):
            label.configure(text="—")

        self.label_detalle_filtro = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.label_detalle_filtro.grid(row=1, column=0, sticky="w", padx=28, pady=(0, 8))

        contenedor_grafico = ctk.CTkFrame(self, corner_radius=16)
        contenedor_grafico.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))
        contenedor_grafico.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            contenedor_grafico,
            text=(
                "Varianza vs. umbral (punteada tenue: umbral de salida; gris: ventana sin filtrar)"
            ),
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self.canvas_ancho = 760
        self.canvas_alto = 200
        self.canvas = tk.Canvas(
            contenedor_grafico,
            width=self.canvas_ancho,
            height=self.canvas_alto,
            bg=COLOR_FONDO_GRAFICO,
            highlightthickness=0,
        )
        self.canvas.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="ew")

        self.label_placeholder = ctk.CTkLabel(
            self,
            text=(
                "Esperando telemetría de src/main.py "
                f"(UDP {HOST_TELEMETRIA}:{PUERTO_TELEMETRIA})..."
            ),
            text_color="gray",
        )
        self.label_placeholder.grid(row=3, column=0, pady=(0, 10))

    @staticmethod
    def _crear_lectura(master, columna: int, titulo: str):
        label_titulo = ctk.CTkLabel(
            master, text=titulo, font=ctk.CTkFont(size=11), text_color="gray"
        )
        label_titulo.grid(row=0, column=columna, padx=8, pady=(14, 0))

        label_valor = ctk.CTkLabel(master, text="—", font=ctk.CTkFont(size=18, weight="bold"))
        label_valor.grid(row=1, column=columna, padx=8, pady=(0, 14))

        return label_titulo, label_valor

    def recibir_muestra(self, muestra: dict) -> None:
        if not self._ultima_muestra_recibida:
            self._ultima_muestra_recibida = True
            self.label_placeholder.grid_remove()

        varianza = float(muestra.get("varianza_promedio", 0.0))
        fs = muestra.get("fs_estimada")
        umbral = float(muestra.get("umbral_actual", self.umbral_actual))
        movimiento = bool(muestra.get("movimiento_detectado", False))
        filtro_aplicado = bool(muestra.get("filtro_aplicado", True))
        estado_filtro = str(muestra.get("estado_filtro", ESTADO_FILTRO_SOS_OK))
        n_paquetes = muestra.get("n_paquetes_ventana")
        supera_umbral = bool(muestra.get("supera_umbral", movimiento))
        racha = int(muestra.get("ventanas_sobre_umbral", 0))
        confirmacion = int(muestra.get("ventanas_confirmacion", 1))
        umbral_salida = muestra.get("umbral_salida")

        self.umbral_actual = umbral
        self.umbral_salida = float(umbral_salida) if umbral_salida is not None else None
        self.historial.append((varianza, filtro_aplicado))

        if not filtro_aplicado:
            self.valor_estado.configure(text="SIN FILTRO", text_color=COLOR_ADVERTENCIA)
            self.valor_filtro.configure(text="CRUDA", text_color=COLOR_ADVERTENCIA)
            self.valor_varianza.configure(
                text=f"{varianza:.4g} (cruda)", text_color=COLOR_SIN_FILTRO
            )
        else:
            if movimiento:
                texto_estado, color_estado = "MOVIMIENTO", COLOR_ALERTA
            elif supera_umbral:
                texto_estado = f"Confirmando {racha}/{confirmacion}"
                color_estado = COLOR_CANDIDATA
            else:
                texto_estado, color_estado = "Reposo", COLOR_REPOSO
            self.valor_estado.configure(text=texto_estado, text_color=color_estado)
            self.valor_filtro.configure(text="SOS ✓", text_color=COLOR_REPOSO)
            self.valor_varianza.configure(text=f"{varianza:.4f}", text_color=("gray10", "gray90"))

        texto_umbral = _formatear_umbral(umbral)
        if self.umbral_salida is not None:
            texto_umbral += f" / {_formatear_umbral(self.umbral_salida)}"
        self.valor_umbral.configure(text=texto_umbral)
        self.valor_fs.configure(text=f"{fs:.1f} Hz" if fs is not None else "N/D")

        n_validas = sum(1 for _, ok in self.historial if ok)
        porcentaje = 100.0 * n_validas / len(self.historial)
        texto_paquetes = f" | {n_paquetes} paquetes en la ventana" if n_paquetes is not None else ""
        self.label_detalle_filtro.configure(
            text=(
                f"Última ventana: {DESCRIPCION_ESTADO_FILTRO.get(estado_filtro, estado_filtro)}"
                f"{texto_paquetes} | ventanas filtradas: "
                f"{n_validas}/{len(self.historial)} ({porcentaje:.0f}%)"
            ),
            text_color="gray" if filtro_aplicado else COLOR_ADVERTENCIA,
        )

        self._redibujar_grafico()

    def _redibujar_grafico(self) -> None:
        self.canvas.delete("all")

        valores = list(self.historial)
        if not valores:
            return

        margen_inferior = 20
        alto_util = self.canvas_alto - margen_inferior

        varianzas_validas = [v for v, ok in valores if ok]
        maximo_valido = max(varianzas_validas) if varianzas_validas else 0.0
        valor_maximo = max(maximo_valido, self.umbral_actual * 1.2, 0.01)

        ancho_barra = self.canvas_ancho / MAX_MUESTRAS_TELEMETRIA

        for i, (valor, filtrada) in enumerate(valores):
            x0 = i * ancho_barra
            x1 = x0 + max(ancho_barra * 0.8, 1)
            altura_barra = min(valor / valor_maximo, 1.0) * alto_util
            y0 = alto_util - altura_barra
            y1 = alto_util
            if not filtrada:
                color = COLOR_SIN_FILTRO
            elif valor >= self.umbral_actual:
                color = COLOR_ALERTA
            else:
                color = COLOR_REPOSO
            self.canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

        if self.umbral_salida is not None and self.umbral_salida > 0:
            y_salida = alto_util - (min(self.umbral_salida / valor_maximo, 1.0) * alto_util)
            self.canvas.create_line(
                0, y_salida, self.canvas_ancho, y_salida,
                fill=COLOR_LINEA_UMBRAL_SALIDA, dash=(2, 4), width=1,
            )

        y_umbral = alto_util - (min(self.umbral_actual / valor_maximo, 1.0) * alto_util)
        self.canvas.create_line(
            0, y_umbral, self.canvas_ancho, y_umbral, fill=COLOR_LINEA_UMBRAL, dash=(4, 2), width=2
        )
        self.canvas.create_text(
            self.canvas_ancho - 6,
            max(y_umbral - 10, 10),
            anchor="e",
            fill=COLOR_LINEA_UMBRAL,
            text=f"umbral = {_formatear_umbral(self.umbral_actual)}",
            font=("", 10),
        )


class PanelHistorial(ctk.CTkScrollableFrame):
    """Resumen, gráfico de eventos por día y tabla paginada de los movimientos guardados."""

    COLUMNAS = [("N°", 60), ("Fecha", 110), ("Inicio", 90), ("Fin", 90), ("Duración", 110), ("Intensidad", 100)]

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self.periodo = "7 días"
        self.pagina = 0
        self.total_eventos = 0
        self._id_consulta = 0
        self._barras: list = []
        self._resumen_diario: list = []
        self._dias_grafico = 7

        self.grid_columnconfigure(0, weight=1)

        # Filtros
        fila_filtros = ctk.CTkFrame(self, fg_color="transparent")
        fila_filtros.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 8))
        fila_filtros.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(fila_filtros, text="Período:").grid(row=0, column=0, padx=(0, 8))
        self.selector_periodo = ctk.CTkSegmentedButton(
            fila_filtros, values=list(PERIODOS_HISTORIAL), command=self._on_cambio_periodo
        )
        self.selector_periodo.set(self.periodo)
        self.selector_periodo.grid(row=0, column=1)
        self.boton_actualizar = ctk.CTkButton(
            fila_filtros, text="Actualizar", width=100, command=self.actualizar
        )
        self.boton_actualizar.grid(row=0, column=2, padx=(12, 0))
        self.label_estado = ctk.CTkLabel(fila_filtros, text="", text_color="gray")
        self.label_estado.grid(row=0, column=3, sticky="e")

        # Resumen del período
        fila_resumen = ctk.CTkFrame(self, corner_radius=16)
        fila_resumen.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        self.valores_resumen = {}
        for columna, (clave, titulo) in enumerate([
            ("cantidad", "Eventos"),
            ("duracion_total", "Tiempo en movimiento"),
            ("duracion_promedio", "Duración promedio"),
            ("varianza_pico", "Intensidad pico"),
        ]):
            fila_resumen.grid_columnconfigure(columna, weight=1)
            _, self.valores_resumen[clave] = PanelTelemetria._crear_lectura(
                fila_resumen, columna, titulo
            )

        # Gráfico
        contenedor_grafico = ctk.CTkFrame(self, corner_radius=16)
        contenedor_grafico.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))
        contenedor_grafico.grid_columnconfigure(0, weight=1)
        self.label_titulo_grafico = ctk.CTkLabel(
            contenedor_grafico, text="Eventos por día", font=ctk.CTkFont(size=13, weight="bold")
        )
        self.label_titulo_grafico.grid(row=0, column=0, sticky="w", padx=16, pady=(10, 2))
        self.canvas = tk.Canvas(
            contenedor_grafico, height=150, bg=COLOR_FONDO_GRAFICO, highlightthickness=0
        )
        self.canvas.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self.canvas.bind("<Configure>", lambda _e: self._dibujar_grafico())
        self.canvas.bind("<Motion>", self._on_mouse_grafico)
        self.canvas.bind("<Leave>", lambda _e: self._ocultar_tooltip())

        # Tabla
        tabla = ctk.CTkFrame(self, corner_radius=16)
        tabla.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 6))
        for columna, (titulo, ancho) in enumerate(self.COLUMNAS):
            tabla.grid_columnconfigure(columna, weight=1, minsize=ancho)
            ctk.CTkLabel(
                tabla, text=titulo, font=ctk.CTkFont(size=12, weight="bold"), text_color="gray"
            ).grid(row=0, column=columna, padx=6, pady=(10, 4))
        self.filas_tabla = []
        for fila in range(EVENTOS_POR_PAGINA):
            celdas = []
            for columna in range(len(self.COLUMNAS)):
                celda = ctk.CTkLabel(tabla, text="", height=24)
                celda.grid(row=fila + 1, column=columna, padx=6, pady=1)
                celdas.append(celda)
            self.filas_tabla.append(celdas)
        self.label_tabla_vacia = ctk.CTkLabel(tabla, text="", text_color="gray")
        self.label_tabla_vacia.grid(
            row=EVENTOS_POR_PAGINA + 1, column=0, columnspan=len(self.COLUMNAS), pady=(0, 8)
        )

        # Paginación
        fila_paginas = ctk.CTkFrame(self, fg_color="transparent")
        fila_paginas.grid(row=4, column=0, pady=(0, 16))
        self.boton_anterior = ctk.CTkButton(
            fila_paginas, text="◀ Anterior", width=110, command=lambda: self._cambiar_pagina(-1)
        )
        self.boton_anterior.grid(row=0, column=0)
        self.label_pagina = ctk.CTkLabel(fila_paginas, text="", width=200)
        self.label_pagina.grid(row=0, column=1, padx=12)
        self.boton_siguiente = ctk.CTkButton(
            fila_paginas, text="Siguiente ▶", width=110, command=lambda: self._cambiar_pagina(1)
        )
        self.boton_siguiente.grid(row=0, column=2)

    # -- Consultas -------------------------------------------------------------
    def _on_cambio_periodo(self, periodo: str) -> None:
        self.periodo = periodo
        self.pagina = 0
        self.actualizar()

    def _cambiar_pagina(self, delta: int) -> None:
        self.pagina += delta
        self.actualizar()

    def actualizar(self) -> None:
        """Vuelve a consultar el período y la página actuales en un hilo aparte."""
        self._id_consulta += 1
        self.label_estado.configure(text="Cargando...")
        self.boton_actualizar.configure(state="disabled")
        dias = PERIODOS_HISTORIAL[self.periodo]
        desde = date.today() - timedelta(days=dias - 1) if dias else None
        dias_grafico = 30 if dias is None or dias > 7 else 7
        threading.Thread(
            target=self._consultar_en_hilo,
            args=(self._id_consulta, desde, self.pagina, dias_grafico),
            daemon=True,
        ).start()

    def _consultar_en_hilo(self, id_consulta: int, desde, pagina: int, dias_grafico: int) -> None:
        """Corre en un hilo secundario: NO debe tocar ningún widget acá."""
        try:
            datos = {
                "estadisticas": obtener_estadisticas_periodo(self.usuario_id, desde=desde),
                "total": contar_eventos_usuario(self.usuario_id, desde=desde),
                "eventos": obtener_historico_usuario(
                    self.usuario_id, limite=EVENTOS_POR_PAGINA,
                    desplazamiento=pagina * EVENTOS_POR_PAGINA, desde=desde,
                ),
                "resumen_diario": obtener_resumen_diario(self.usuario_id, dias=dias_grafico),
                "dias_grafico": dias_grafico,
            }
        except Exception as e:
            logger.error(f"Error al consultar el historial: {e}")
            datos = None
        self.after(0, self._mostrar_datos, id_consulta, datos)

    # -- Presentación ----------------------------------------------------------
    def _mostrar_datos(self, id_consulta: int, datos: Optional[dict]) -> None:
        if id_consulta != self._id_consulta:
            return  # llegó la respuesta de una consulta vieja
        self.boton_actualizar.configure(state="normal")
        if datos is None:
            self.label_estado.configure(text="No se pudo consultar la base.", text_color=COLOR_ERROR)
            return
        self.label_estado.configure(
            text=f"Actualizado {datetime.now():%H:%M:%S}", text_color="gray"
        )

        estadisticas = datos["estadisticas"]
        self.valores_resumen["cantidad"].configure(text=str(estadisticas["cantidad"]))
        self.valores_resumen["duracion_total"].configure(
            text=_formatear_duracion(estadisticas["duracion_total"])
        )
        self.valores_resumen["duracion_promedio"].configure(
            text=_formatear_duracion(estadisticas["duracion_promedio"]) if estadisticas["cantidad"] else "—"
        )
        pico = estadisticas["varianza_pico"]
        self.valores_resumen["varianza_pico"].configure(text="—" if pico is None else f"{pico:.2f}")

        self._resumen_diario = datos["resumen_diario"]
        self._dias_grafico = datos["dias_grafico"]
        self.label_titulo_grafico.configure(
            text=f"Eventos por día (últimos {self._dias_grafico} días)"
        )
        self._dibujar_grafico()

        self.total_eventos = datos["total"]
        paginas = max(1, math.ceil(self.total_eventos / EVENTOS_POR_PAGINA))
        if self.pagina >= paginas:
            self.pagina = paginas - 1
            self.actualizar()
            return
        self._llenar_tabla(datos["eventos"])
        self.label_pagina.configure(
            text=f"Página {self.pagina + 1} de {paginas}  ·  {self.total_eventos} eventos"
        )
        self.boton_anterior.configure(state="normal" if self.pagina > 0 else "disabled")
        self.boton_siguiente.configure(state="normal" if self.pagina < paginas - 1 else "disabled")

    def _llenar_tabla(self, eventos: list) -> None:
        for fila, celdas in enumerate(self.filas_tabla):
            if fila < len(eventos):
                evento = eventos[fila]
                fin = evento.get("timestamp_fin")
                textos = [
                    str(evento["id"]),
                    f"{evento['timestamp']:%d/%m/%Y}",
                    f"{evento['timestamp']:%H:%M:%S}",
                    f"{fin:%H:%M:%S}" if fin else "en curso",
                    _formatear_duracion(evento.get("duracion_segundos")) if fin else "—",
                    "—" if evento.get("varianza_maxima") is None else f"{evento['varianza_maxima']:.2f}",
                ]
            else:
                textos = [""] * len(celdas)
            for celda, texto in zip(celdas, textos):
                celda.configure(text=texto)
        self.label_tabla_vacia.configure(
            text="" if eventos else "No hay movimientos registrados en este período."
        )

    def _dibujar_grafico(self) -> None:
        self.canvas.delete("all")
        ancho = max(self.canvas.winfo_width(), 200)
        alto = int(self.canvas.cget("height"))
        margen_izq, margen_der, margen_sup, margen_inf = 34, 10, 16, 22
        alto_util = alto - margen_sup - margen_inf
        ancho_util = ancho - margen_izq - margen_der

        hoy = date.today()
        por_dia = {fila["fecha"]: fila for fila in self._resumen_diario}
        dias = [hoy - timedelta(days=i) for i in range(self._dias_grafico - 1, -1, -1)]
        cantidades = [int(por_dia[d]["cantidad"]) if d in por_dia else 0 for d in dias]

        maximo = max(cantidades + [1])
        paso = max(1, math.ceil(maximo / 4))
        tope = paso * math.ceil(maximo / paso)

        def y_de(valor: float) -> float:
            return margen_sup + alto_util * (1 - valor / tope)

        # Grilla y eje Y (enteros)
        for valor in range(0, tope + 1, paso):
            y = y_de(valor)
            self.canvas.create_line(margen_izq, y, ancho - margen_der, y, fill=COLOR_GRILLA)
            self.canvas.create_text(
                margen_izq - 6, y, text=str(valor), anchor="e", fill=COLOR_TEXTO_EJE, font=("", 9)
            )

        ancho_slot = ancho_util / len(dias)
        ancho_barra = max(ancho_slot - 2, 1) if len(dias) > 7 else ancho_slot * 0.55
        cada_cuanto_etiqueta = 1 if len(dias) <= 7 else 5
        indice_maximo = cantidades.index(max(cantidades))
        self._barras = []
        for i, (dia, cantidad) in enumerate(zip(dias, cantidades)):
            centro = margen_izq + ancho_slot * (i + 0.5)
            x0, x1 = centro - ancho_barra / 2, centro + ancho_barra / 2
            if cantidad > 0:
                self.canvas.create_rectangle(
                    x0, y_de(cantidad), x1, y_de(0), fill=COLOR_BARRA_HISTORIAL, outline=""
                )
            if i == indice_maximo and cantidad > 0:
                self.canvas.create_text(
                    centro, y_de(cantidad) - 7, text=str(cantidad), fill=COLOR_TEXTO_DATO,
                    font=("", 9), tags="etiqueta_maximo",
                )
            if (len(dias) - 1 - i) % cada_cuanto_etiqueta == 0:
                etiqueta = "Hoy" if dia == hoy else f"{dia:%d/%m}"
                self.canvas.create_text(
                    centro, alto - margen_inf + 12, text=etiqueta, fill=COLOR_TEXTO_EJE, font=("", 9)
                )
            fila = por_dia.get(dia)
            duracion = float(fila["duracion_total"]) if fila else 0.0
            self._barras.append((margen_izq + ancho_slot * i, margen_izq + ancho_slot * (i + 1), dia, cantidad, duracion))

    def _ocultar_tooltip(self) -> None:
        self.canvas.delete("tooltip")
        self.canvas.itemconfigure("etiqueta_maximo", state="normal")

    def _on_mouse_grafico(self, evento) -> None:
        self._ocultar_tooltip()
        for x0, x1, dia, cantidad, duracion in self._barras:
            if x0 <= evento.x < x1:
                texto = f"{dia:%d/%m}: {cantidad} evento{'s' if cantidad != 1 else ''}"
                if cantidad:
                    texto += f" · {_formatear_duracion(duracion)}"
                ancho = int(self.canvas.winfo_width())
                ancla = "e" if evento.x > ancho * 0.6 else "w"
                desplazamiento = -10 if ancla == "e" else 10
                item = self.canvas.create_text(
                    evento.x + desplazamiento, 12, text=texto, anchor=ancla,
                    fill=COLOR_TEXTO_DATO, font=("", 10), tags="tooltip",
                )
                x_a, y_a, x_b, y_b = self.canvas.bbox(item)
                fondo = self.canvas.create_rectangle(
                    x_a - 6, y_a - 3, x_b + 6, y_b + 3, fill="#2b2b2b", outline="#555555",
                    tags="tooltip",
                )
                self.canvas.create_line(
                    (x0 + x1) / 2, 18, (x0 + x1) / 2, int(self.canvas.cget("height")) - 22,
                    fill="#555555", dash=(2, 2), tags="tooltip",
                )
                self.canvas.tag_raise(fondo)
                self.canvas.tag_raise(item)
                self.canvas.itemconfigure("etiqueta_maximo", state="hidden")
                break


class FramePrincipal(ctk.CTkFrame):
    """Pestañas de la aplicación y receptor de telemetría compartido."""

    def __init__(self, master, usuario_id: int, username: str):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self.username = username

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        encabezado = ctk.CTkFrame(self, fg_color="transparent")
        encabezado.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 0))
        encabezado.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            encabezado,
            text=f"Sesión activa: {username}",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        tabview = ctk.CTkTabview(self, command=self._on_cambio_pestania)
        self.tabview = tabview
        tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        tab_monitoreo = tabview.add("Monitoreo")
        tab_configuracion = tabview.add("Configuración")
        tab_historial = tabview.add("Historial")
        tab_telemetria = tabview.add("Telemetría Live")

        tab_monitoreo.grid_columnconfigure(0, weight=1)
        tab_configuracion.grid_columnconfigure(0, weight=1)
        tab_telemetria.grid_columnconfigure(0, weight=1)
        tab_historial.grid_columnconfigure(0, weight=1)
        tab_historial.grid_rowconfigure(0, weight=1)

        self.panel_monitoreo = PanelMonitoreo(tab_monitoreo, usuario_id=usuario_id)
        self.panel_monitoreo.grid(row=0, column=0, sticky="nsew")

        self.panel_configuracion = PanelConfiguracion(tab_configuracion, usuario_id=usuario_id)
        self.panel_configuracion.grid(row=0, column=0, sticky="nsew")

        self.panel_historial = PanelHistorial(tab_historial, usuario_id=usuario_id)
        self.panel_historial.grid(row=0, column=0, sticky="nsew")

        self.panel_telemetria = PanelTelemetria(tab_telemetria, usuario_id=usuario_id)
        self.panel_telemetria.grid(row=0, column=0, sticky="nsew")

        # Un solo receptor UDP para toda la ventana; reparte las muestras a los paneles
        self.receptor = ReceptorTelemetria(
            host=HOST_TELEMETRIA, port=PUERTO_TELEMETRIA, on_muestra=self._on_muestra_recibida
        )
        self.receptor.iniciar()

    def _on_cambio_pestania(self) -> None:
        if self.tabview.get() == "Historial":
            self.panel_historial.actualizar()

    def _on_muestra_recibida(self, muestra: dict) -> None:
        self.after(0, self._distribuir_muestra, muestra)

    def _distribuir_muestra(self, muestra: dict) -> None:
        self.panel_monitoreo.recibir_muestra(muestra)
        self.panel_telemetria.recibir_muestra(muestra)

    def detener(self) -> None:
        self.receptor.detener()
        self.panel_monitoreo.detener()


class DashboardApp(ctk.CTk):
    """Ventana principal."""

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Sistema de Detección Pasiva de Movimiento - CSI Wi-Fi")
        self.geometry("940x660")
        self.minsize(760, 540)

        self.usuario_id: Optional[int] = None
        self.username: Optional[str] = None
        self.frame_actual: Optional[ctk.CTkFrame] = None

        self.protocol("WM_DELETE_WINDOW", self._on_cerrar)

        self._mostrar_login()

    def _mostrar_login(self) -> None:
        if self.frame_actual is not None:
            self.frame_actual.destroy()
        self.frame_actual = FrameLogin(self, on_login_exitoso=self._on_login_exitoso)
        self.frame_actual.pack(fill="both", expand=True)

    def _on_login_exitoso(self, usuario_id: int, username: str) -> None:
        self.usuario_id = usuario_id
        self.username = username

        self.frame_actual.destroy()
        self.frame_actual = FramePrincipal(self, usuario_id=usuario_id, username=username)
        self.frame_actual.pack(fill="both", expand=True)

        logger.info(f"Sesión iniciada: '{username}' (usuario_id={usuario_id}).")

    def _on_cerrar(self) -> None:
        if isinstance(self.frame_actual, FramePrincipal):
            self.frame_actual.detener()
        self.destroy()


if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()
