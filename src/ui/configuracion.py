"""Pantalla de configuración: sensibilidad, historial y alertas."""

import math
from typing import Optional

import customtkinter as ctk

from src.acciones.notificacion_windows import NotificadorWindows
from src.database.database import actualizar_configuracion_usuario, obtener_configuracion_usuario
from src.ui.componentes import boton, en_hilo, etiqueta, formatear_umbral, panel
from src.ui.tema import COLORES, MARGEN, fuente

# Slider de umbral en escala logarítmica
UMBRAL_MIN = 0.01
UMBRAL_MAX = 10_000.0
PASOS_SLIDER = 600


def _umbral_a_posicion(umbral: float) -> float:
    return math.log10(min(max(float(umbral), UMBRAL_MIN), UMBRAL_MAX))


def _posicion_a_umbral(posicion: float) -> float:
    valor = 10 ** float(posicion)
    if valor >= 100:
        return float(round(valor))
    if valor >= 10:
        return round(valor, 1)
    if valor >= 1:
        return round(valor, 2)
    return round(valor, 3)


class PantallaConfiguracion(ctk.CTkScrollableFrame):
    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self._guardada: Optional[dict] = None
        # Umbral elegido; sólo cambia si se mueve el slider (el slider redondea a sus pasos)
        self._umbral: Optional[float] = None
        self.grid_columnconfigure(0, weight=1)

        # Sensibilidad
        sens = self._seccion(0, "Sensibilidad",
                             "Cuánto tiene que alterarse el canal para considerar que hubo movimiento.")
        fila = ctk.CTkFrame(sens, fg_color="transparent")
        fila.grid(row=2, column=0, sticky="ew", padx=24)
        fila.grid_columnconfigure(1, weight=1)
        etiqueta(fila, "Más sensible", 12, suave=True).grid(row=0, column=0)
        self.slider = ctk.CTkSlider(
            fila, from_=math.log10(UMBRAL_MIN), to=math.log10(UMBRAL_MAX), number_of_steps=PASOS_SLIDER,
            button_color=COLORES["senal"], button_hover_color=COLORES["senal"],
            progress_color=COLORES["senal"], command=self._on_slider,
        )
        self.slider.grid(row=0, column=1, sticky="ew", padx=12)
        etiqueta(fila, "Menos sensible", 12, suave=True).grid(row=0, column=2)
        self.label_umbral = etiqueta(fila, "—", 18, negrita=True, width=70)
        self.label_umbral.grid(row=0, column=3, padx=(16, 0))
        etiqueta(sens, "Ubicalo entre la intensidad que ves en reposo y la que ves con movimiento "
                       "(pantalla Diagnóstico).", 12, suave=True).grid(row=3, column=0, sticky="w", padx=24, pady=(8, 18))

        # Historial
        hist = self._seccion(1, "Historial", "Guarda cada movimiento con su hora, duración e intensidad.")
        self.switch_guardar = ctk.CTkSwitch(hist, text="Guardar los movimientos en el historial", font=fuente(13),
                                            progress_color=COLORES["senal"], command=self._on_cambio)
        self.switch_guardar.grid(row=2, column=0, sticky="w", padx=24, pady=(0, 18))

        # Alertas
        alertas = self._seccion(2, "Alertas", "Notificación de Windows con sonido al terminar cada movimiento.")
        fila_alertas = ctk.CTkFrame(alertas, fg_color="transparent")
        fila_alertas.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 18))
        fila_alertas.grid_columnconfigure(0, weight=1)
        self.switch_alertas = ctk.CTkSwitch(fila_alertas, text="Enviar alertas", font=fuente(13),
                                            progress_color=COLORES["senal"], command=self._on_cambio)
        self.switch_alertas.grid(row=0, column=0, sticky="w")
        self.label_prueba = etiqueta(fila_alertas, "", 12, suave=True)
        self.label_prueba.grid(row=0, column=1, padx=12)
        self.boton_probar = boton(fila_alertas, "Probar alerta", primario=False, width=120, command=self._probar_alerta)
        self.boton_probar.grid(row=0, column=2)

        # Guardar
        acciones = ctk.CTkFrame(self, fg_color="transparent")
        acciones.grid(row=3, column=0, sticky="ew", padx=MARGEN - 6, pady=(4, 10))
        acciones.grid_columnconfigure(0, weight=1)
        self.label_guardado = etiqueta(acciones, "", 12, suave=True)
        self.label_guardado.grid(row=0, column=0, sticky="e", padx=14)
        self.boton_guardar = boton(acciones, "Guardar cambios", width=150, command=self._guardar, state="disabled")
        self.boton_guardar.grid(row=0, column=1)

        self.label_guardado.configure(text="Cargando configuración...")
        en_hilo(self, obtener_configuracion_usuario, self._mostrar, usuario_id)

    def _seccion(self, fila: int, titulo: str, descripcion: str) -> ctk.CTkFrame:
        p = panel(self)
        p.grid(row=fila, column=0, sticky="ew", padx=MARGEN - 6, pady=(0, 12))
        p.grid_columnconfigure(0, weight=1)
        etiqueta(p, titulo, 15, negrita=True).grid(row=0, column=0, sticky="w", padx=24, pady=(16, 0))
        etiqueta(p, descripcion, 12, suave=True).grid(row=1, column=0, sticky="w", padx=24, pady=(0, 10))
        return p

    def _valores(self) -> dict:
        return {
            "umbral_sensibilidad": self._umbral,
            "guardar_eventos": bool(self.switch_guardar.get()),
            "enviar_alertas": bool(self.switch_alertas.get()),
        }

    def _mostrar(self, config: Optional[dict]) -> None:
        if config is None:
            self.label_guardado.configure(text="No se pudo cargar la configuración.", text_color=COLORES["error"])
            return
        self._umbral = float(config["umbral_sensibilidad"])
        self.slider.set(_umbral_a_posicion(self._umbral))
        for switch, clave in ((self.switch_guardar, "guardar_eventos"), (self.switch_alertas, "enviar_alertas")):
            switch.select() if config[clave] else switch.deselect()
        self._guardada = self._valores()
        self.label_guardado.configure(text="")
        self._on_cambio()

    def _on_slider(self, posicion: float) -> None:
        self._umbral = _posicion_a_umbral(posicion)
        self._on_cambio()

    def _on_cambio(self) -> None:
        if self._umbral is None:
            return
        valores = self._valores()
        self.label_umbral.configure(text=formatear_umbral(valores["umbral_sensibilidad"]))
        if self._guardada is None:
            return
        hay_cambios = valores != self._guardada
        self.boton_guardar.configure(state="normal" if hay_cambios else "disabled")
        self.label_guardado.configure(text="Hay cambios sin guardar" if hay_cambios else "",
                                      text_color=COLORES["texto_suave"])

    def _guardar(self) -> None:
        valores = self._valores()
        self.boton_guardar.configure(state="disabled", text="Guardando...")
        en_hilo(
            self,
            lambda: actualizar_configuracion_usuario(
                self.usuario_id, valores["umbral_sensibilidad"],
                guardar_eventos=valores["guardar_eventos"], enviar_alertas=valores["enviar_alertas"]),
            lambda exito: self._guardado(exito, valores),
        )

    def _guardado(self, exito: Optional[bool], valores: dict) -> None:
        self.boton_guardar.configure(text="Guardar cambios")
        if exito:
            self._guardada = valores
            self._on_cambio()
            self.label_guardado.configure(text="Cambios guardados. Se aplican en unos segundos.", text_color=COLORES["ok"])
        else:
            self.boton_guardar.configure(state="normal")
            self.label_guardado.configure(text="No se pudieron guardar los cambios.", text_color=COLORES["error"])

    def _probar_alerta(self) -> None:
        self.boton_probar.configure(state="disabled")
        en_hilo(self, lambda: NotificadorWindows().notificar_prueba(), self._prueba_enviada)

    def _prueba_enviada(self, ok: Optional[bool]) -> None:
        self.boton_probar.configure(state="normal")
        self.label_prueba.configure(
            text="Alerta enviada." if ok else "Las alertas sólo funcionan en Windows.",
            text_color=COLORES["ok"] if ok else COLORES["aviso"],
        )

    def detener(self) -> None:
        pass
