"""
dashboard.py
============

Interfaz gráfica de usuario (MVP 3) del Sistema de Detección Pasiva de
Movimiento por CSI Wi-Fi. Construida con `customtkinter` sobre la capa
de persistencia ya existente (`src.database.database`), sin acceder a
MySQL directamente: todo pasa por las mismas funciones que ya usan
`src/main.py` y el resto del pipeline.

Pantallas:
    1. Login: valida credenciales contra `verificar_usuario`.
    2. Panel principal, con tres secciones (CTkTabview):
        - Monitoreo: tarjeta grande de estado del canal, que se
          refresca sola cada pocos segundos consultando
          `obtener_historico_usuario` para ver si hubo un evento de
          movimiento reciente.
        - Configuración: muestra los parámetros actuales del usuario
          (`obtener_configuracion_usuario`) y permite ajustar el umbral
          de sensibilidad con un slider, persistiendo el cambio con
          `actualizar_configuracion_usuario`.
        - Telemetría Live: recibe, por UDP local (ver
          `src/common/telemetria_ipc.py`), la varianza y la fs real que
          `src/main.py` mide en CADA ventana procesada (~32 veces por
          segundo con la Raspberry Pi real), y las grafica en vivo.
          Pensada para diagnóstico: permite ver a simple vista si la
          varianza está pegada arriba del umbral de forma sostenida
          (síntoma del bug de fs que se corrigió en signal_filter.py) en
          lugar de tener que leer el archivo de log línea por línea.

Concurrencia:
    Tkinter (y por lo tanto customtkinter) no es thread-safe: ningún
    widget puede tocarse desde un hilo que no sea el principal (el que
    corre `mainloop()`). Tanto las consultas a MySQL como la recepción
    de telemetría UDP pueden llegar en cualquier momento y no deben
    congelar la interfaz, así que cada una corre en su propio
    `threading.Thread` de background; esos hilos NUNCA actualizan
    widgets directamente, sino que agendan la actualización de vuelta en
    el hilo principal con `self.after(0, callback, ...)`, que es la
    forma segura de comunicar hilos con el mainloop de Tkinter.

Requisitos:
    pip install customtkinter

Autor: Trabajo Integrador Final - Módulo de Interfaz Gráfica (MVP 3)
"""

import logging
import socket
import sys
import threading
import tkinter as tk
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Optional

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Resolución de rutas / imports
# ---------------------------------------------------------------------------
# Este archivo vive en <raiz_proyecto>/src/ui/dashboard.py, por lo que hay
# que subir 2 niveles para llegar a la raíz del proyecto (igual que hace
# parser_csi.py con su propia ubicación en src/parser/).
RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

from src.database.database import (
    actualizar_configuracion_usuario,
    obtener_configuracion_usuario,
    obtener_historico_usuario,
    verificar_usuario,
)
from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA, deserializar_muestra

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("dashboard")

# ---------------------------------------------------------------------------
# Constantes de la interfaz
# ---------------------------------------------------------------------------

# Cada cuánto se refresca automáticamente el panel de monitoreo (ms).
INTERVALO_ACTUALIZACION_MS = 3000

# Un evento se considera "reciente" (dispara la alerta roja) si ocurrió
# dentro de esta cantidad de segundos respecto del momento de la consulta.
VENTANA_ALERTA_SEGUNDOS = 10

# Rango del slider de umbral de sensibilidad.
UMBRAL_MIN = 0.0
UMBRAL_MAX = 10.0

COLOR_ALERTA = "#c0392b"   # rojo
COLOR_REPOSO = "#27ae60"   # verde
COLOR_ERROR = "#e74c3c"
COLOR_EXITO = "#2ecc71"

# Cuántas muestras de telemetría se conservan para el gráfico en vivo.
# A ~32 muestras/seg (fs real ~650Hz, paso de deslizamiento 20), esto
# equivale a unos 4-5 segundos de historial visible.
MAX_MUESTRAS_TELEMETRIA = 150

COLOR_FONDO_GRAFICO = "#1a1a1a"
COLOR_LINEA_UMBRAL = "#f1c40f"  # amarillo, para distinguirse de las barras rojo/verde


# ---------------------------------------------------------------------------
# Pantalla de Login
# ---------------------------------------------------------------------------
class FrameLogin(ctk.CTkFrame):
    """
    Formulario de inicio de sesión. Valida credenciales contra la base
    de datos a través de `verificar_usuario`, sin bloquear la interfaz
    mientras dura la consulta.
    """

    def __init__(self, master: "DashboardApp", on_login_exitoso):
        """
        Args:
            master: ventana principal (DashboardApp).
            on_login_exitoso: callback `(usuario_id, username) -> None`
                invocado cuando la autenticación es exitosa.
        """
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
        """Corre en un hilo secundario: NO debe tocar ningún widget acá."""
        try:
            usuario_id = verificar_usuario(username, password)
        except Exception as e:
            usuario_id = None
            logger.error(f"Error inesperado al verificar usuario: {e}")

        # Volvemos al hilo principal para actualizar la interfaz.
        self.after(0, self._procesar_resultado, usuario_id, username)

    def _procesar_resultado(self, usuario_id: Optional[int], username: str) -> None:
        self.boton_login.configure(state="normal", text="Ingresar")

        if usuario_id is None:
            self.label_error.configure(text="Usuario o contraseña incorrectos.")
            return

        self.on_login_exitoso(usuario_id, username)


# ---------------------------------------------------------------------------
# Panel de Monitoreo (tarjeta de estado del canal)
# ---------------------------------------------------------------------------
class PanelMonitoreo(ctk.CTkFrame):
    """
    Tarjeta grande de estado del canal. Se refresca sola cada
    `INTERVALO_ACTUALIZACION_MS` consultando el último evento de
    movimiento del usuario (`obtener_historico_usuario`).
    """

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self._detenido = False

        self.grid_columnconfigure(0, weight=1)

        self.tarjeta = ctk.CTkFrame(self, corner_radius=20, fg_color=COLOR_REPOSO, height=220)
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

        self.label_ultima_consulta = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.label_ultima_consulta.grid(row=1, column=0, pady=(0, 10))

        # Primer refresco inmediato, y de ahí en más según el intervalo.
        self._programar_actualizacion(inmediato=True)

    # -- Ciclo de actualización ------------------------------------------
    def _programar_actualizacion(self, inmediato: bool = False) -> None:
        if self._detenido:
            return
        demora = 0 if inmediato else INTERVALO_ACTUALIZACION_MS
        self.after(demora, self._disparar_consulta)

    def _disparar_consulta(self) -> None:
        if self._detenido:
            return
        hilo = threading.Thread(target=self._consultar_en_hilo, daemon=True)
        hilo.start()

    def _consultar_en_hilo(self) -> None:
        """Corre en un hilo secundario: NO debe tocar ningún widget acá."""
        try:
            historico = obtener_historico_usuario(self.usuario_id)
        except Exception as e:
            historico = []
            logger.error(f"Error al consultar histórico de movimiento: {e}")

        self.after(0, self._actualizar_tarjeta, historico)

    def _actualizar_tarjeta(self, historico: list) -> None:
        if self._detenido:
            return

        ultimo_evento = historico[0] if historico else None

        if ultimo_evento is not None:
            antiguedad_seg = (datetime.now() - ultimo_evento["timestamp"]).total_seconds()
        else:
            antiguedad_seg = None

        if ultimo_evento is not None and 0 <= antiguedad_seg <= VENTANA_ALERTA_SEGUNDOS:
            self._mostrar_alerta(ultimo_evento)
        else:
            self._mostrar_reposo()

        self.label_ultima_consulta.configure(
            text=f"Última consulta: {datetime.now().strftime('%H:%M:%S')}"
        )

        # Reprograma el siguiente ciclo (recién ahora, para no acumular
        # consultas superpuestas si MySQL tarda más que el intervalo).
        self._programar_actualizacion()

    # -- Estados visuales --------------------------------------------------
    def _mostrar_alerta(self, evento: dict) -> None:
        self.tarjeta.configure(fg_color=COLOR_ALERTA)
        self.label_estado.configure(text="¡MOVIMIENTO DETECTADO!")
        self.label_detalle.configure(
            text=(
                f"Varianza: {evento['varianza_maxima']:.4f}   |   "
                f"Duración: {evento['duracion_segundos']}s   |   "
                f"Hora: {evento['timestamp'].strftime('%H:%M:%S')}"
            )
        )

    def _mostrar_reposo(self) -> None:
        self.tarjeta.configure(fg_color=COLOR_REPOSO)
        self.label_estado.configure(text="Entorno Seguro / En Reposo")
        self.label_detalle.configure(text="Sin movimiento detectado recientemente.")

    def detener(self) -> None:
        """Frena el ciclo de refresco (llamar al cerrar la aplicación)."""
        self._detenido = True


# ---------------------------------------------------------------------------
# Panel de Configuración
# ---------------------------------------------------------------------------
class PanelConfiguracion(ctk.CTkFrame):
    """
    Muestra los parámetros actuales del usuario y permite modificar el
    umbral de sensibilidad, persistiendo el cambio en
    `configuracion_sistema` a través de `actualizar_configuracion_usuario`.
    """

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
        ).grid(row=0, column=0, sticky="w", padx=24, pady=(20, 4))

        self.label_canal = ctk.CTkLabel(panel, text="Canal Wi-Fi: -")
        self.label_canal.grid(row=1, column=0, sticky="w", padx=24, pady=2)

        self.label_bssid = ctk.CTkLabel(panel, text="BSSID objetivo: -")
        self.label_bssid.grid(row=2, column=0, sticky="w", padx=24, pady=(2, 16))

        ctk.CTkLabel(
            panel, text="Umbral de sensibilidad (varianza mínima para disparar una alerta):",
        ).grid(row=3, column=0, sticky="w", padx=24, pady=(4, 2))

        fila_slider = ctk.CTkFrame(panel, fg_color="transparent")
        fila_slider.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 4))
        fila_slider.grid_columnconfigure(0, weight=1)

        self.slider_umbral = ctk.CTkSlider(
            fila_slider,
            from_=UMBRAL_MIN,
            to=UMBRAL_MAX,
            number_of_steps=200,
            command=self._on_slider_cambia,
        )
        self.slider_umbral.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.slider_umbral.set(0.0)

        self.label_umbral_valor = ctk.CTkLabel(fila_slider, text="0.00", width=50)
        self.label_umbral_valor.grid(row=0, column=1)

        self.boton_guardar = ctk.CTkButton(
            panel, text="Guardar cambios", command=self._guardar_cambios
        )
        self.boton_guardar.grid(row=5, column=0, sticky="w", padx=24, pady=(16, 4))

        self.label_estado_guardado = ctk.CTkLabel(panel, text="", text_color="gray")
        self.label_estado_guardado.grid(row=6, column=0, sticky="w", padx=24, pady=(0, 20))

        self._cargar_configuracion()

    # -- Carga inicial -------------------------------------------------
    def _cargar_configuracion(self) -> None:
        self.label_estado_guardado.configure(text="Cargando configuración...", text_color="gray")
        hilo = threading.Thread(target=self._cargar_en_hilo, daemon=True)
        hilo.start()

    def _cargar_en_hilo(self) -> None:
        """Corre en un hilo secundario: NO debe tocar ningún widget acá."""
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
        self.label_canal.configure(text=f"Canal Wi-Fi: {config['canal_wifi']}")
        self.label_bssid.configure(
            text=f"BSSID objetivo: {config['bssid_objetivo'] or '(sin configurar)'}"
        )
        self.slider_umbral.set(float(config["umbral_sensibilidad"]))
        self.label_umbral_valor.configure(text=f"{float(config['umbral_sensibilidad']):.2f}")
        self.label_estado_guardado.configure(text="")

    def _on_slider_cambia(self, valor: float) -> None:
        self.label_umbral_valor.configure(text=f"{float(valor):.2f}")

    # -- Guardado --------------------------------------------------------
    def _guardar_cambios(self) -> None:
        if self._config_actual is None:
            self.label_estado_guardado.configure(
                text="Todavía no se cargó la configuración actual.", text_color=COLOR_ERROR
            )
            return

        nuevo_umbral = float(self.slider_umbral.get())
        canal_actual = self._config_actual["canal_wifi"]
        bssid_actual = self._config_actual["bssid_objetivo"]

        self.boton_guardar.configure(state="disabled", text="Guardando...")
        self.label_estado_guardado.configure(text="")

        hilo = threading.Thread(
            target=self._guardar_en_hilo,
            args=(nuevo_umbral, canal_actual, bssid_actual),
            daemon=True,
        )
        hilo.start()

    def _guardar_en_hilo(self, umbral: float, canal: int, bssid: Optional[str]) -> None:
        """Corre en un hilo secundario: NO debe tocar ningún widget acá."""
        try:
            exito = actualizar_configuracion_usuario(self.usuario_id, umbral, canal, bssid)
        except Exception as e:
            exito = False
            logger.error(f"Error al guardar configuración: {e}")

        self.after(0, self._procesar_resultado_guardado, exito, umbral)

    def _procesar_resultado_guardado(self, exito: bool, umbral_guardado: float) -> None:
        self.boton_guardar.configure(state="normal", text="Guardar cambios")

        if exito:
            self._config_actual["umbral_sensibilidad"] = umbral_guardado
            self.label_estado_guardado.configure(
                text="✔ Configuración guardada correctamente.", text_color=COLOR_EXITO
            )
        else:
            self.label_estado_guardado.configure(
                text="✘ No se pudo guardar la configuración.", text_color=COLOR_ERROR
            )


# ---------------------------------------------------------------------------
# Receptor de telemetría UDP (background)
# ---------------------------------------------------------------------------
class ReceptorTelemetria:
    """
    Escucha datagramas UDP de telemetría enviados por `src/main.py` en
    un hilo de background dedicado. El socket se abre con un timeout
    corto (no bloqueante indefinidamente) para poder revisar
    periódicamente si se pidió detener el hilo al cerrar la ventana, en
    vez de quedar bloqueado para siempre en `recvfrom()`.

    El callback `on_muestra` se invoca DESDE ESTE HILO DE BACKGROUND —
    quien lo registre es responsable de no tocar widgets directamente
    ahí adentro, y en cambio usar `self.after(0, ...)` para volver al
    hilo principal (ver `PanelTelemetria._on_muestra_recibida`).
    """

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
                    continue  # normal: reintenta y vuelve a chequear _detener
                except OSError:
                    break

                muestra = deserializar_muestra(datos)
                if muestra is not None and self.on_muestra is not None:
                    self.on_muestra(muestra)


# ---------------------------------------------------------------------------
# Pestaña de Telemetría en Tiempo Real
# ---------------------------------------------------------------------------
class PanelTelemetria(ctk.CTkFrame):
    """
    Pestaña de diagnóstico "Telemetría Live": recibe, por UDP, la
    varianza promedio y la fs real de cada ventana que procesa
    `src/main.py`, y las muestra en vivo — lecturas numéricas más un
    gráfico de barras con la varianza reciente contra la línea de
    umbral vigente.

    Pensada específicamente para poder diagnosticar visualmente
    problemas como el que motivó esta pestaña: si la varianza queda
    pegada por encima del umbral de forma sostenida (en vez de subir y
    bajar con el movimiento real), el gráfico lo muestra de inmediato
    sin tener que leer el log línea por línea.
    """

    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id

        self.historial_varianza: Deque[float] = deque(maxlen=MAX_MUESTRAS_TELEMETRIA)
        self.umbral_actual: float = 0.0
        self._ultima_muestra_recibida = False

        self.grid_columnconfigure(0, weight=1)

        # --- Fila de lecturas numéricas ---
        fila_lecturas = ctk.CTkFrame(self, corner_radius=16)
        fila_lecturas.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        for col in range(4):
            fila_lecturas.grid_columnconfigure(col, weight=1)

        self.label_estado_lectura, self.valor_estado = self._crear_lectura(
            fila_lecturas, 0, "Estado"
        )
        self.label_varianza_lectura, self.valor_varianza = self._crear_lectura(
            fila_lecturas, 1, "Varianza instantánea"
        )
        self.label_umbral_lectura, self.valor_umbral = self._crear_lectura(
            fila_lecturas, 2, "Umbral vigente"
        )
        self.label_fs_lectura, self.valor_fs = self._crear_lectura(
            fila_lecturas, 3, "Frecuencia real"
        )

        self.valor_estado.configure(text="Sin datos")
        self.valor_varianza.configure(text="—")
        self.valor_umbral.configure(text="—")
        self.valor_fs.configure(text="—")

        # --- Gráfico en vivo ---
        contenedor_grafico = ctk.CTkFrame(self, corner_radius=16)
        contenedor_grafico.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        contenedor_grafico.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            contenedor_grafico,
            text="Varianza reciente vs. umbral (últimas muestras)",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        # Canvas nativo de Tkinter: customtkinter no trae un widget de
        # gráfico propio, y traer una librería de plotting pesada
        # (matplotlib) para dibujar barras a ~32Hz sería sobrekill. Un
        # Canvas con rectángulos simples es más que suficiente y muy
        # liviano de redibujar en cada muestra.
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
        self.label_placeholder.grid(row=2, column=0, pady=(0, 10))

        self.receptor = ReceptorTelemetria(
            host=HOST_TELEMETRIA, port=PUERTO_TELEMETRIA, on_muestra=self._on_muestra_recibida
        )
        self.receptor.iniciar()

    @staticmethod
    def _crear_lectura(master, columna: int, titulo: str):
        """Crea una lectura numérica (título chico + valor grande) en una columna del grid."""
        label_titulo = ctk.CTkLabel(
            master, text=titulo, font=ctk.CTkFont(size=11), text_color="gray"
        )
        label_titulo.grid(row=0, column=columna, padx=12, pady=(14, 0))

        label_valor = ctk.CTkLabel(master, text="—", font=ctk.CTkFont(size=20, weight="bold"))
        label_valor.grid(row=1, column=columna, padx=12, pady=(0, 14))

        return label_titulo, label_valor

    # -- Recepción (hilo de background) -------------------------------
    def _on_muestra_recibida(self, muestra: dict) -> None:
        """Corre en el hilo del ReceptorTelemetria: NO tocar widgets acá."""
        self.after(0, self._actualizar_con_muestra, muestra)

    # -- Actualización de UI (hilo principal) --------------------------
    def _actualizar_con_muestra(self, muestra: dict) -> None:
        if not self._ultima_muestra_recibida:
            self._ultima_muestra_recibida = True
            self.label_placeholder.grid_remove()  # ya no hace falta el placeholder

        varianza = float(muestra.get("varianza_promedio", 0.0))
        fs = muestra.get("fs_estimada")
        umbral = float(muestra.get("umbral_actual", self.umbral_actual))
        movimiento = bool(muestra.get("movimiento_detectado", False))

        self.umbral_actual = umbral
        self.historial_varianza.append(varianza)

        self.valor_estado.configure(
            text="MOVIMIENTO" if movimiento else "Reposo",
            text_color=COLOR_ALERTA if movimiento else COLOR_REPOSO,
        )
        self.valor_varianza.configure(text=f"{varianza:.4f}")
        self.valor_umbral.configure(text=f"{umbral:.2f}")
        self.valor_fs.configure(text=f"{fs:.1f} Hz" if fs is not None else "N/D")

        self._redibujar_grafico()

    def _redibujar_grafico(self) -> None:
        self.canvas.delete("all")

        valores = list(self.historial_varianza)
        if not valores:
            return

        margen_inferior = 20
        alto_util = self.canvas_alto - margen_inferior

        # Escala vertical dinámica: se ajusta al valor más alto visible
        # (incluyendo el umbral, para que la línea siempre sea visible
        # aunque la varianza esté muy por debajo).
        valor_maximo = max(max(valores), self.umbral_actual * 1.2, 0.01)

        ancho_barra = self.canvas_ancho / MAX_MUESTRAS_TELEMETRIA

        for i, valor in enumerate(valores):
            x0 = i * ancho_barra
            x1 = x0 + max(ancho_barra * 0.8, 1)
            altura_barra = min(valor / valor_maximo, 1.0) * alto_util
            y0 = alto_util - altura_barra
            y1 = alto_util
            color = COLOR_ALERTA if valor >= self.umbral_actual else COLOR_REPOSO
            self.canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

        # Línea de referencia del umbral vigente.
        y_umbral = alto_util - (min(self.umbral_actual / valor_maximo, 1.0) * alto_util)
        self.canvas.create_line(
            0, y_umbral, self.canvas_ancho, y_umbral, fill=COLOR_LINEA_UMBRAL, dash=(4, 2), width=2
        )
        self.canvas.create_text(
            self.canvas_ancho - 6,
            max(y_umbral - 10, 10),
            anchor="e",
            fill=COLOR_LINEA_UMBRAL,
            text=f"umbral = {self.umbral_actual:.2f}",
            font=("", 10),
        )

    def detener(self) -> None:
        """Frena el hilo receptor de UDP (llamar al cerrar la aplicación)."""
        self.receptor.detener()


# ---------------------------------------------------------------------------
# Panel principal (post-login): agrupa Monitoreo + Configuración en tabs
# ---------------------------------------------------------------------------
class FramePrincipal(ctk.CTkFrame):
    """
    Contenedor post-login. Muestra un encabezado con el usuario actual y
    un `CTkTabview` con las secciones de Monitoreo y Configuración.
    """

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

        tabview = ctk.CTkTabview(self)
        tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        tab_monitoreo = tabview.add("Monitoreo")
        tab_configuracion = tabview.add("Configuración")
        tab_telemetria = tabview.add("Telemetría Live")

        tab_monitoreo.grid_columnconfigure(0, weight=1)
        tab_configuracion.grid_columnconfigure(0, weight=1)
        tab_telemetria.grid_columnconfigure(0, weight=1)

        self.panel_monitoreo = PanelMonitoreo(tab_monitoreo, usuario_id=usuario_id)
        self.panel_monitoreo.grid(row=0, column=0, sticky="nsew")

        self.panel_configuracion = PanelConfiguracion(tab_configuracion, usuario_id=usuario_id)
        self.panel_configuracion.grid(row=0, column=0, sticky="nsew")

        self.panel_telemetria = PanelTelemetria(tab_telemetria, usuario_id=usuario_id)
        self.panel_telemetria.grid(row=0, column=0, sticky="nsew")

    def detener(self) -> None:
        """Propaga la señal de detención a los sub-paneles con timers/hilos activos."""
        self.panel_monitoreo.detener()
        self.panel_telemetria.detener()


# ---------------------------------------------------------------------------
# Ventana principal de la aplicación
# ---------------------------------------------------------------------------
class DashboardApp(ctk.CTk):
    """
    Ventana raíz de la aplicación. Arranca mostrando `FrameLogin`; tras
    una autenticación exitosa, la reemplaza por `FramePrincipal`.
    """

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Sistema de Detección Pasiva de Movimiento - CSI Wi-Fi")
        self.geometry("880x640")
        self.minsize(700, 520)

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
        """
        Antes de cerrar la ventana, frena cualquier ciclo de refresco
        (`root.after`) pendiente en los paneles con timers activos, para
        que no queden callbacks intentando actualizar widgets ya destruidos.
        """
        if isinstance(self.frame_actual, FramePrincipal):
            self.frame_actual.detener()
        self.destroy()


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()
