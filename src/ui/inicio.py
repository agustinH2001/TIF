"""Pantalla de inicio: estado actual, traza del canal en vivo y actividad del día."""

import tkinter as tk
from collections import deque
from datetime import date, datetime, timedelta
from typing import Optional

import customtkinter as ctk

from src.database.database import (
    obtener_configuracion_usuario,
    obtener_estadisticas_periodo,
    obtener_historico_usuario,
    obtener_ultimo_evento,
)
from src.ui.componentes import (
    cifra, en_hilo, escala_log, etiqueta, formatear_duracion, hace, panel,
)
from src.ui.tema import COLORES, MARGEN, fuente_canvas

SEGUNDOS_TRAZA = 30
# main.py procesa una ventana cada 0.2 s de datos: 150 ventanas = 30 s
VENTANAS_TRAZA = SEGUNDOS_TRAZA * 5
INTERVALO_CONSULTA_MS = 3000
# Después de terminar un movimiento, durante cuántos segundos se muestra cuánto duró
SEGUNDOS_RESUMEN_FIN = 10
ALTO_TRAZA = 170


class PantallaInicio(ctk.CTkFrame):
    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self._activa = True

        # Las barras se ubican por orden de ventana y no por hora de llegada: la
        # telemetría llega en ráfagas y por hora se superpondrían
        self._muestras: deque = deque(maxlen=VENTANAS_TRAZA)  # (varianza, filtrada, en_movimiento)
        self._umbral: Optional[float] = None
        self._movimiento_vivo = False
        self._inicio_vivo: Optional[datetime] = None
        self._sensor_en_linea = False
        self._sensor_de_otro_usuario = False
        self._ultimo_evento: Optional[dict] = None
        self._config: Optional[dict] = None
        self._eventos_24h: list = []

        self.grid_columnconfigure(0, weight=1)

        # Estado principal y traza
        self.hero = panel(self)
        self.hero.grid(row=0, column=0, sticky="ew", padx=MARGEN)
        self.hero.grid_columnconfigure(0, weight=1)
        self.franja = ctk.CTkFrame(self.hero, height=4, corner_radius=2, fg_color="transparent")
        self.franja.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(10, 0))
        self.label_estado = etiqueta(self.hero, "Conectando...", 30, negrita=True)
        self.label_estado.grid(row=1, column=0, sticky="w", padx=26, pady=(8, 0))
        self.label_detalle = etiqueta(self.hero, "", 14, suave=True, anchor="w", justify="left", wraplength=560)
        self.label_detalle.grid(row=2, column=0, sticky="w", padx=26)
        lado = ctk.CTkFrame(self.hero, fg_color="transparent")
        lado.grid(row=1, column=1, rowspan=2, sticky="ne", padx=26, pady=(12, 0))
        self.label_alertas = etiqueta(lado, "", 12, suave=True)
        self.label_alertas.pack(anchor="e")
        self.label_historial = etiqueta(lado, "", 12, suave=True)
        self.label_historial.pack(anchor="e")
        self.canvas_traza = tk.Canvas(self.hero, height=ALTO_TRAZA, bg=COLORES["superficie"], highlightthickness=0)
        self.canvas_traza.grid(row=3, column=0, columnspan=2, sticky="ew", padx=26, pady=(14, 20))
        self.canvas_traza.bind("<Configure>", lambda _e: self._dibujar_traza())

        # Datos del día
        datos = panel(self)
        datos.grid(row=1, column=0, sticky="ew", padx=MARGEN, pady=14)
        self.cifras = {}
        for columna, (clave, descripcion) in enumerate([
            ("cantidad", "movimientos hoy"),
            ("duracion_total", "en movimiento hoy"),
            ("ultimo", "duró el último"),
        ]):
            datos.grid_columnconfigure(columna * 2, weight=1)
            marco, self.cifras[clave] = cifra(datos, "—", descripcion)
            marco.grid(row=0, column=columna * 2, sticky="w", padx=26, pady=16)
            if columna < 2:
                ctk.CTkFrame(datos, width=1, height=44, fg_color=COLORES["linea"]).grid(row=0, column=columna * 2 + 1)

        # Actividad de las últimas 24 h
        actividad = panel(self)
        actividad.grid(row=2, column=0, sticky="ew", padx=MARGEN)
        actividad.grid_columnconfigure(0, weight=1)
        etiqueta(actividad, "Actividad de las últimas 24 horas", 14, negrita=True).grid(
            row=0, column=0, sticky="w", padx=26, pady=(16, 0))
        self.canvas_24h = tk.Canvas(actividad, height=70, bg=COLORES["superficie"], highlightthickness=0)
        self.canvas_24h.grid(row=1, column=0, sticky="ew", padx=26, pady=(8, 16))
        self.canvas_24h.bind("<Configure>", lambda _e: self._dibujar_24h())

        self._consultar()

    # -- Datos en vivo ------------------------------------------------------------
    def recibir_muestra(self, muestra: dict) -> None:
        movimiento = bool(muestra.get("movimiento_detectado", False))
        self._muestras.append((float(muestra.get("varianza_promedio", 0.0)),
                               bool(muestra.get("filtro_aplicado", True)), movimiento))
        self._umbral = float(muestra.get("umbral_actual", 0.0)) or None

        if movimiento != self._movimiento_vivo:
            self._movimiento_vivo = movimiento
            if movimiento:
                self._inicio_vivo = datetime.now()
            else:
                # Se consulta la base enseguida para mostrar la duración real
                self.after(700, self._consultar, False)
            self._actualizar_estado()
            self._dibujar_24h()
        self._dibujar_traza()

    def set_sensor_en_linea(self, en_linea: bool, de_otro_usuario: bool = False) -> None:
        cambio_otro = de_otro_usuario != self._sensor_de_otro_usuario
        self._sensor_de_otro_usuario = de_otro_usuario
        if cambio_otro and not en_linea:
            self._actualizar_estado()
        if en_linea != self._sensor_en_linea:
            self._sensor_en_linea = en_linea
            if not en_linea:
                self._movimiento_vivo = False
                self._muestras.clear()
                self._dibujar_traza()
            self._actualizar_estado()

    def tick(self) -> None:
        """Llamado cada segundo por la aplicación para refrescar los textos relativos."""
        self._actualizar_estado()

    # -- Consultas a la base ---------------------------------------------------
    def _consultar(self, reprogramar: bool = True) -> None:
        if not self._activa:
            return

        def consultar():
            hace_24h = datetime.now() - timedelta(hours=24)
            eventos = obtener_historico_usuario(self.usuario_id, limite=1000, desde=hace_24h.date())
            return {
                "ultimo": obtener_ultimo_evento(self.usuario_id),
                "hoy": obtener_estadisticas_periodo(self.usuario_id, desde=date.today()),
                "eventos_24h": [e for e in eventos if e["timestamp"] >= hace_24h],
                "config": obtener_configuracion_usuario(self.usuario_id),
            }

        def mostrar(datos):
            if not self._activa:
                return
            if datos is not None:
                self._ultimo_evento = datos["ultimo"]
                self._config = datos["config"] or self._config
                self._eventos_24h = datos["eventos_24h"]
                hoy = datos["hoy"]
                self.cifras["cantidad"].configure(text=str(hoy["cantidad"]))
                self.cifras["duracion_total"].configure(text=formatear_duracion(hoy["duracion_total"]))
                ultimo = self._ultimo_evento
                if ultimo is None:
                    texto_ultimo = "—"
                elif ultimo["timestamp_fin"] is None:
                    texto_ultimo = "en curso"
                else:
                    texto_ultimo = formatear_duracion(ultimo["duracion_segundos"])
                self.cifras["ultimo"].configure(text=texto_ultimo)
                self._actualizar_estado()
                self._dibujar_24h()
            if reprogramar:
                self.after(INTERVALO_CONSULTA_MS, self._consultar)

        en_hilo(self, consultar, mostrar)

    # -- Presentación ----------------------------------------------------------
    def _actualizar_estado(self) -> None:
        ahora = datetime.now()
        evento = self._ultimo_evento

        if self._config is not None:
            self.label_alertas.configure(
                text="Alertas activadas" if self._config["enviar_alertas"] else "Alertas desactivadas")
            self.label_historial.configure(
                text="Guardando en el historial" if self._config["guardar_eventos"] else "Historial desactivado")

        if not self._sensor_en_linea and self._sensor_de_otro_usuario:
            titulo, color, franja = "Sensor en uso por otro usuario", COLORES["texto_suave"], "transparent"
            detalle = ("El sensor está registrando para otra cuenta. Si acabás de iniciar sesión, "
                       "cambia solo en unos segundos; si no, main.py se inició con un usuario fijo (--usuario).")
        elif not self._sensor_en_linea:
            titulo, color = "Sin datos del sensor", COLORES["texto_suave"]
            detalle = "Revisá que main.py esté corriendo y que la Raspberry Pi esté enviando la captura."
            franja = "transparent"
        elif self._movimiento_vivo:
            inicio = evento["timestamp"] if evento and evento["timestamp_fin"] is None else self._inicio_vivo
            inicio = inicio or ahora
            titulo, color, franja = "Movimiento detectado", COLORES["movimiento"], COLORES["movimiento"]
            detalle = f"En curso desde las {inicio:%H:%M:%S}, {hace(inicio)}"
        else:
            titulo, color, franja = "Sin movimiento", COLORES["texto"], "transparent"
            fin = evento["timestamp_fin"] if evento else None
            if fin is not None and (ahora - fin).total_seconds() <= SEGUNDOS_RESUMEN_FIN:
                detalle = f"El último movimiento terminó {hace(fin)} y duró {formatear_duracion(evento['duracion_segundos'])}"
            elif fin is not None:
                formato = "%H:%M:%S" if fin.date() == ahora.date() else "%d/%m a las %H:%M"
                detalle = f"Último movimiento: {fin.strftime(formato)}"
            else:
                detalle = "Todavía no hay movimientos guardados."

        self.label_estado.configure(text=titulo, text_color=color)
        self.label_detalle.configure(text=detalle)
        self.franja.configure(fg_color=franja)

    def _dibujar_traza(self) -> None:
        c = self.canvas_traza
        c.delete("all")
        ancho, alto = max(c.winfo_width(), 200), ALTO_TRAZA
        base_y = alto - 24
        validas = [v for v, ok, _ in self._muestras if ok]
        umbral = self._umbral
        tope = max(validas + [umbral * 4 if umbral else 1.0, 0.5])

        def y_de(valor: float) -> float:
            return base_y - (base_y - 16) * escala_log(valor, tope)

        # Una barra por ventana: cian en reposo, coral durante un movimiento y
        # una marca baja gris para las ventanas sin filtrar (su valor no es comparable)
        espacio = ancho / VENTANAS_TRAZA
        ancho_barra = max(espacio - 1, 1)
        desplazamiento = VENTANAS_TRAZA - len(self._muestras)  # alineadas a la derecha ("ahora")
        for indice, (valor, filtrada, en_movimiento) in enumerate(self._muestras):
            x0 = (indice + desplazamiento) * espacio
            x1 = x0 + ancho_barra
            if not filtrada:
                c.create_rectangle(x0, base_y - 6, x1, base_y, fill=COLORES["sin_datos"], outline="")
                continue
            color = COLORES["movimiento"] if en_movimiento else COLORES["senal"]
            c.create_rectangle(x0, y_de(valor), x1, base_y, fill=color, outline="")

        if umbral and self._muestras:
            yu = y_de(umbral)
            c.create_line(0, yu, ancho, yu, fill=COLORES["texto_suave"], dash=(3, 4))
            texto = c.create_text(4, yu - 10, text="umbral", anchor="w", fill=COLORES["texto_suave"], font=fuente_canvas())
            xa, ya, xb, yb = c.bbox(texto)
            fondo = c.create_rectangle(xa - 4, ya - 1, xb + 4, yb + 1, fill=COLORES["superficie"], outline="")
            c.tag_raise(texto, fondo)
        c.create_text(0, alto - 2, text=f"hace {SEGUNDOS_TRAZA} s", anchor="sw", fill=COLORES["texto_suave"], font=fuente_canvas())
        c.create_text(ancho, alto - 2, text="ahora", anchor="se", fill=COLORES["texto_suave"], font=fuente_canvas())
        if not self._muestras:
            c.create_text(ancho / 2, base_y / 2, text="Esperando datos del sensor",
                          fill=COLORES["texto_suave"], font=fuente_canvas(12))

    def _dibujar_24h(self) -> None:
        c = self.canvas_24h
        c.delete("all")
        ancho = max(c.winfo_width(), 200)
        eje_y = 40
        ahora = datetime.now()
        c.create_line(0, eje_y, ancho, eje_y, fill=COLORES["linea"], width=2)
        for horas in range(0, 25, 3):
            x = ancho * horas / 24
            c.create_line(x, eje_y - 3, x, eje_y + 3, fill=COLORES["linea"])
            ancla = "w" if horas == 0 else ("e" if horas == 24 else "center")
            c.create_text(x, 58, text="ahora" if horas == 24 else f"-{24 - horas} h",
                          fill=COLORES["texto_suave"], font=fuente_canvas(), anchor=ancla)
        tope = max([e["varianza_maxima"] or 0 for e in self._eventos_24h] + [1.0])
        for evento in self._eventos_24h:
            horas_atras = (ahora - evento["timestamp"]).total_seconds() / 3600
            x = ancho * (1 - horas_atras / 24)
            alto = 8 + 20 * escala_log(evento["varianza_maxima"] or 0, tope)
            en_curso = evento["timestamp_fin"] is None
            c.create_line(x, eje_y - alto, x, eje_y, width=3, capstyle="round",
                          fill=COLORES["movimiento"] if en_curso else COLORES["senal"])
        if self._movimiento_vivo:
            c.create_line(ancho - 2, eje_y - 28, ancho - 2, eje_y, width=3, capstyle="round",
                          fill=COLORES["movimiento"])

    def detener(self) -> None:
        self._activa = False
