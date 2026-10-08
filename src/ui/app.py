"""Ventana principal: login, barra lateral de navegación y encabezado con el estado del sensor."""

import logging
import tkinter as tk
from datetime import datetime
from typing import Optional

import customtkinter as ctk

from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA
from src.database.database import establecer_usuario_activo
from src.ui.componentes import ReceptorTelemetria, en_hilo, etiqueta, icono
from src.ui.configuracion import PantallaConfiguracion
from src.ui.diagnostico import PantallaDiagnostico
from src.ui.historial import PantallaHistorial
from src.ui.inicio import PantallaInicio
from src.ui.login import PantallaLogin
from src.ui.tema import COLORES, MARGEN, fuente

logger = logging.getLogger("dashboard")

# Sin telemetría durante este tiempo, el sensor se considera fuera de línea
SEGUNDOS_SIN_TELEMETRIA = 5

PANTALLAS = [
    ("Inicio", "inicio", PantallaInicio),
    ("Historial", "historial", PantallaHistorial),
    ("Configuración", "configuracion", PantallaConfiguracion),
    ("Diagnóstico", "diagnostico", PantallaDiagnostico),
]


class VistaPrincipal(ctk.CTkFrame):
    """Barra lateral, encabezado y las pantallas de la aplicación."""

    def __init__(self, master, usuario_id: int, usuario: str, on_cerrar_sesion):
        super().__init__(master, fg_color=COLORES["fondo"], corner_radius=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.usuario_id = usuario_id
        self._ultima_muestra: Optional[datetime] = None
        self._ultima_muestra_ajena: Optional[datetime] = None
        self._fs: Optional[float] = None
        self._activa = True

        # Barra lateral
        lateral = ctk.CTkFrame(self, fg_color=COLORES["lateral"], corner_radius=0, width=220)
        lateral.grid(row=0, column=0, sticky="ns")
        lateral.grid_propagate(False)
        lateral.grid_columnconfigure(0, weight=1)
        lateral.grid_rowconfigure(len(PANTALLAS) + 2, weight=1)
        marca = ctk.CTkFrame(lateral, fg_color="transparent")
        marca.grid(row=0, column=0, sticky="w", padx=20, pady=(24, 26))
        ctk.CTkLabel(marca, text="", image=icono("logo_senal", 30)).grid(row=0, column=0, rowspan=2, padx=(0, 10))
        etiqueta(marca, "Detector CSI", 17, negrita=True).grid(row=0, column=1, sticky="w")
        etiqueta(marca, "Movimiento por Wi-Fi", 11, suave=True).grid(row=1, column=1, sticky="w")

        self.items_nav = {}
        for fila, (titulo, clave_icono, _) in enumerate(PANTALLAS, start=1):
            marco = ctk.CTkFrame(lateral, fg_color="transparent", corner_radius=8, height=42)
            marco.grid(row=fila, column=0, sticky="ew", padx=12, pady=2)
            marco.grid_propagate(False)
            marco.grid_columnconfigure(1, weight=1)
            marco.grid_rowconfigure(0, weight=1)
            indicador = ctk.CTkFrame(marco, width=3, height=20, corner_radius=2, fg_color="transparent")
            indicador.grid(row=0, column=0, padx=(6, 4))
            boton_nav = ctk.CTkButton(
                marco, text=titulo, anchor="w", font=fuente(14), height=38, corner_radius=8,
                fg_color="transparent", hover_color=COLORES["superficie_alta"],
                text_color=COLORES["texto_suave"], image=icono(f"{clave_icono}_suave", 18),
                compound="left", command=lambda t=titulo: self.mostrar(t),
            )
            boton_nav.grid(row=0, column=1, sticky="ew", padx=(0, 4))
            self.items_nav[titulo] = (marco, indicador, boton_nav, clave_icono)

        pie = ctk.CTkFrame(lateral, fg_color="transparent")
        pie.grid(row=len(PANTALLAS) + 3, column=0, sticky="ew", padx=20, pady=20)
        etiqueta(pie, usuario, 13, negrita=True).pack(anchor="w")
        ctk.CTkButton(pie, text="Cerrar sesión", font=fuente(12), anchor="w", width=0, height=26,
                      fg_color="transparent", hover_color=COLORES["superficie_alta"],
                      text_color=COLORES["texto_suave"], image=icono("cerrar_sesion_suave", 14),
                      compound="left", command=on_cerrar_sesion).pack(anchor="w", pady=(2, 0))

        # Encabezado y contenido
        contenido = ctk.CTkFrame(self, fg_color=COLORES["fondo"], corner_radius=0)
        contenido.grid(row=0, column=1, sticky="nsew")
        contenido.grid_columnconfigure(0, weight=1)
        contenido.grid_rowconfigure(1, weight=1)
        encabezado = ctk.CTkFrame(contenido, fg_color="transparent")
        encabezado.grid(row=0, column=0, sticky="ew", padx=MARGEN, pady=(22, 14))
        encabezado.grid_columnconfigure(0, weight=1)
        self.label_titulo = etiqueta(encabezado, "", 24, negrita=True)
        self.label_titulo.grid(row=0, column=0, sticky="w")
        sensor = ctk.CTkFrame(encabezado, fg_color=COLORES["superficie"], corner_radius=16, height=32)
        sensor.grid(row=0, column=1, sticky="e")
        self.punto = tk.Canvas(sensor, width=10, height=10, bg=COLORES["superficie"], highlightthickness=0)
        self.punto.grid(row=0, column=0, padx=(14, 6), pady=8)
        self.label_sensor = etiqueta(sensor, "", 12)
        self.label_sensor.grid(row=0, column=1)
        self.label_fs = etiqueta(sensor, "", 12, suave=True)
        self.label_fs.grid(row=0, column=2, padx=(8, 14))

        self.pantallas = {}
        for titulo, _, clase in PANTALLAS:
            pantalla = clase(contenido, usuario_id=usuario_id)
            pantalla.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
            pantalla.grid_remove()
            self.pantallas[titulo] = pantalla

        # Un solo receptor de telemetría para toda la ventana
        self.receptor = ReceptorTelemetria(HOST_TELEMETRIA, PUERTO_TELEMETRIA, self._on_muestra)
        self.receptor.iniciar()

        self.actual: Optional[str] = None
        self.mostrar("Inicio")
        self._actualizar_sensor()
        self._tick()

    def mostrar(self, titulo: str) -> None:
        if self.actual == titulo:
            return
        if self.actual is not None:
            self.pantallas[self.actual].grid_remove()
        self.actual = titulo
        self.pantallas[titulo].grid()
        self.label_titulo.configure(text=titulo)
        for nombre, (marco, indicador, boton_nav, clave_icono) in self.items_nav.items():
            activo = nombre == titulo
            marco.configure(fg_color=COLORES["superficie_alta"] if activo else "transparent")
            indicador.configure(fg_color=COLORES["senal"] if activo else "transparent")
            boton_nav.configure(
                text_color=COLORES["texto"] if activo else COLORES["texto_suave"],
                font=fuente(14, activo),
                image=icono(f"{clave_icono}_{'activo' if activo else 'suave'}", 18),
                hover_color=COLORES["superficie_alta"],
            )
        if titulo == "Historial":
            self.pantallas[titulo].actualizar()

    # -- Telemetría ------------------------------------------------------------
    def _on_muestra(self, muestra: dict) -> None:
        """Corre en el hilo del receptor: pasa la muestra al hilo de la interfaz."""
        try:
            self.after(0, self._distribuir, muestra)
        except RuntimeError:
            pass

    def _distribuir(self, muestra: dict) -> None:
        if not self._activa:
            return
        # main.py corriendo para otra cuenta: no se muestran sus datos como propios
        usuario_sensor = muestra.get("usuario_id")
        if usuario_sensor is not None and usuario_sensor != self.usuario_id:
            otro_antes = self._sensor_de_otro_usuario()
            self._ultima_muestra_ajena = datetime.now()
            if not otro_antes:
                self._actualizar_sensor()
            return
        estaba_en_linea = self._sensor_en_linea()
        self._ultima_muestra = datetime.now()
        self._fs = muestra.get("fs_estimada")
        if not estaba_en_linea:
            self._actualizar_sensor()
        self.pantallas["Inicio"].recibir_muestra(muestra)
        self.pantallas["Diagnóstico"].recibir_muestra(muestra)

    def _sensor_en_linea(self) -> bool:
        return (self._ultima_muestra is not None
                and (datetime.now() - self._ultima_muestra).total_seconds() <= SEGUNDOS_SIN_TELEMETRIA)

    def _sensor_de_otro_usuario(self) -> bool:
        return (not self._sensor_en_linea() and self._ultima_muestra_ajena is not None
                and (datetime.now() - self._ultima_muestra_ajena).total_seconds() <= SEGUNDOS_SIN_TELEMETRIA)

    def _actualizar_sensor(self) -> None:
        en_linea = self._sensor_en_linea()
        de_otro = self._sensor_de_otro_usuario()
        if en_linea:
            color, texto = COLORES["ok"], "Sensor en línea"
        elif de_otro:
            color, texto = COLORES["aviso"], "Sensor en uso por otro usuario"
        else:
            color, texto = COLORES["sin_datos"], "Sensor sin datos"
        self.punto.delete("all")
        self.punto.create_oval(1, 1, 9, 9, outline="", fill=color)
        self.label_sensor.configure(text=texto)
        self.label_fs.configure(text=f"{self._fs:.0f} Hz" if en_linea and self._fs else "")
        self.pantallas["Inicio"].set_sensor_en_linea(en_linea, de_otro_usuario=de_otro)

    def _tick(self) -> None:
        if not self._activa:
            return
        self._actualizar_sensor()
        self.pantallas["Inicio"].tick()
        self.after(1000, self._tick)

    def detener(self) -> None:
        self._activa = False
        self.receptor.detener()
        for pantalla in self.pantallas.values():
            pantalla.detener()


class DashboardApp(ctk.CTk):
    def __init__(self):
        super().__init__(fg_color=COLORES["fondo"])
        ctk.set_appearance_mode("dark")
        self.title("Detector de movimiento CSI")
        self.geometry("1120x760")
        self.minsize(1000, 680)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.vista: Optional[ctk.CTkFrame] = None
        self.protocol("WM_DELETE_WINDOW", self._on_cerrar)
        self._mostrar_login()

    def _cambiar_vista(self, vista: ctk.CTkFrame) -> None:
        if isinstance(self.vista, VistaPrincipal):
            self.vista.detener()
        if self.vista is not None:
            self.vista.destroy()
        self.vista = vista
        vista.grid(row=0, column=0, sticky="nsew")

    def _mostrar_login(self) -> None:
        self._cambiar_vista(PantallaLogin(self, on_login_exitoso=self._on_login_exitoso))

    def _on_login_exitoso(self, usuario_id: int, usuario: str) -> None:
        logger.info(f"Sesión iniciada: '{usuario}' (usuario_id={usuario_id}).")
        # El sensor (main.py) pasa a registrar para quien inició sesión
        en_hilo(self, establecer_usuario_activo, lambda _ok: None, usuario_id)
        self._cambiar_vista(VistaPrincipal(self, usuario_id, usuario, on_cerrar_sesion=self._mostrar_login))

    def _on_cerrar(self) -> None:
        if isinstance(self.vista, VistaPrincipal):
            self.vista.detener()
        self.destroy()
