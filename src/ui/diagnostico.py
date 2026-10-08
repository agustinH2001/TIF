"""Pantalla de diagnóstico: lecturas técnicas de cada ventana procesada por main.py."""

import tkinter as tk
from collections import deque
from typing import Deque, Optional, Tuple

import customtkinter as ctk

from src.common.telemetria_ipc import HOST_TELEMETRIA, PUERTO_TELEMETRIA
from src.processing.signal_filter import DESCRIPCION_ESTADO_FILTRO, ESTADO_FILTRO_SOS_OK
from src.ui.componentes import cifra, etiqueta, formatear_umbral, panel
from src.ui.tema import COLORES, MARGEN, fuente_canvas

MAX_MUESTRAS = 150  # unos 30 s a 5 ventanas por segundo
ALTO_GRAFICO = 220


class PantallaDiagnostico(ctk.CTkFrame):
    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self.historial: Deque[Tuple[float, bool]] = deque(maxlen=MAX_MUESTRAS)
        self.umbral = 0.0
        self.umbral_salida: Optional[float] = None
        self.grid_columnconfigure(0, weight=1)

        lecturas = panel(self)
        lecturas.grid(row=0, column=0, sticky="ew", padx=MARGEN)
        self.valores = {}
        for columna, (clave, descripcion) in enumerate([
            ("estado", "estado del detector"), ("filtro", "filtro"), ("varianza", "intensidad (varianza)"),
            ("umbral", "umbral de entrada / salida"), ("fs", "paquetes por segundo"),
        ]):
            lecturas.grid_columnconfigure(columna, weight=1)
            marco, self.valores[clave] = cifra(lecturas, "—", descripcion, tamanio=18)
            marco.grid(row=0, column=columna, sticky="w", padx=20, pady=16)

        self.label_detalle = etiqueta(
            self, f"Esperando telemetría de main.py (UDP {HOST_TELEMETRIA}:{PUERTO_TELEMETRIA}).", 12, suave=True)
        self.label_detalle.grid(row=1, column=0, sticky="w", padx=MARGEN + 4, pady=10)

        grafico = panel(self)
        grafico.grid(row=2, column=0, sticky="ew", padx=MARGEN)
        grafico.grid_columnconfigure(0, weight=1)
        etiqueta(grafico, "Intensidad de cada ventana frente al umbral", 14, negrita=True).grid(
            row=0, column=0, sticky="w", padx=22, pady=(14, 0))
        etiqueta(grafico, "Línea punteada: umbral de entrada. Punteada tenue: umbral de salida. "
                          "Gris: ventana sin filtrar.", 12, suave=True).grid(row=1, column=0, sticky="w", padx=22)
        self.canvas = tk.Canvas(grafico, height=ALTO_GRAFICO, bg=COLORES["superficie"], highlightthickness=0)
        self.canvas.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 16))
        self.canvas.bind("<Configure>", lambda _e: self._dibujar())

    def recibir_muestra(self, muestra: dict) -> None:
        varianza = float(muestra.get("varianza_promedio", 0.0))
        fs = muestra.get("fs_estimada")
        movimiento = bool(muestra.get("movimiento_detectado", False))
        filtrada = bool(muestra.get("filtro_aplicado", True))
        estado_filtro = str(muestra.get("estado_filtro", ESTADO_FILTRO_SOS_OK))
        supera = bool(muestra.get("supera_umbral", movimiento))
        racha = int(muestra.get("ventanas_sobre_umbral", 0))
        confirmacion = int(muestra.get("ventanas_confirmacion", 1))
        self.umbral = float(muestra.get("umbral_actual", self.umbral))
        salida = muestra.get("umbral_salida")
        self.umbral_salida = float(salida) if salida is not None else None
        self.historial.append((varianza, filtrada))

        if not filtrada:
            estado, color = "Sin filtrar", COLORES["aviso"]
        elif movimiento:
            estado, color = "Movimiento", COLORES["movimiento"]
        elif supera:
            estado, color = f"Confirmando {racha}/{confirmacion}", COLORES["aviso"]
        else:
            estado, color = "Reposo", COLORES["ok"]
        self.valores["estado"].configure(text=estado, text_color=color)
        self.valores["filtro"].configure(text="Aplicado" if filtrada else "No aplicado",
                                         text_color=COLORES["texto"] if filtrada else COLORES["aviso"])
        self.valores["varianza"].configure(text=f"{varianza:.3f}" if filtrada else f"{varianza:.3g} (cruda)")
        texto_umbral = formatear_umbral(self.umbral)
        if self.umbral_salida is not None:
            texto_umbral += f" / {formatear_umbral(self.umbral_salida)}"
        self.valores["umbral"].configure(text=texto_umbral)
        self.valores["fs"].configure(text=f"{fs:.0f}" if fs is not None else "—")

        validas = sum(1 for _, ok in self.historial if ok)
        n_paquetes = muestra.get("n_paquetes_ventana")
        self.label_detalle.configure(
            text=(f"Última ventana: {DESCRIPCION_ESTADO_FILTRO.get(estado_filtro, estado_filtro)}, "
                  f"{n_paquetes} paquetes. Ventanas filtradas en los últimos 30 s: "
                  f"{validas} de {len(self.historial)}."),
            text_color=COLORES["texto_suave"] if filtrada else COLORES["aviso"],
        )
        self._dibujar()

    def _dibujar(self) -> None:
        c = self.canvas
        c.delete("all")
        valores = list(self.historial)
        ancho, alto = max(c.winfo_width(), 200), ALTO_GRAFICO
        alto_util = alto - 6
        if not valores:
            return
        validas = [v for v, ok in valores if ok]
        tope = max(max(validas) if validas else 0.0, self.umbral * 1.2, 0.01)
        ancho_barra = ancho / MAX_MUESTRAS
        for i, (valor, filtrada) in enumerate(valores):
            x0 = i * ancho_barra
            y0 = alto_util - min(valor / tope, 1.0) * (alto_util - 10)
            if not filtrada:
                color = COLORES["sin_datos"]
            elif valor >= self.umbral:
                color = COLORES["movimiento"]
            else:
                color = COLORES["senal"]
            c.create_rectangle(x0, y0, x0 + max(ancho_barra - 1, 1), alto_util, fill=color, outline="")
        for umbral, patron, color in ((self.umbral_salida, (2, 4), COLORES["linea"]),
                                      (self.umbral, (4, 3), COLORES["texto_suave"])):
            if umbral:
                y = alto_util - min(umbral / tope, 1.0) * (alto_util - 10)
                c.create_line(0, y, ancho, y, fill=color, dash=patron)
        y = alto_util - min(self.umbral / tope, 1.0) * (alto_util - 10)
        c.create_text(ancho - 4, max(y - 9, 8), text=f"umbral {formatear_umbral(self.umbral)}",
                      anchor="e", fill=COLORES["texto_suave"], font=fuente_canvas())

    def detener(self) -> None:
        pass
