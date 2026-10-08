"""Colores, tipografía y medidas de la interfaz."""

import sys

import customtkinter as ctk

FUENTE = "Segoe UI" if sys.platform == "win32" else "Inter"

COLORES = {
    "fondo": "#1A2230",
    "lateral": "#1F2836",
    "superficie": "#232D3C",
    "superficie_alta": "#2D3949",
    "linea": "#3A4759",
    "texto": "#E8EDF3",
    "texto_suave": "#9AA8BA",
    "senal": "#4CC3D9",
    "movimiento": "#F0654F",
    "ok": "#3DBE8B",
    "aviso": "#E8A33D",
    "error": "#F0654F",
    "boton": "#2F7FA0",
    "boton_hover": "#286E8B",
    "sin_datos": "#6B7A8F",
}

MARGEN = 28
RADIO_PANEL = 14
RADIO_BOTON = 8


def fuente(tamanio: int, negrita: bool = False) -> ctk.CTkFont:
    return ctk.CTkFont(family=FUENTE, size=tamanio, weight="bold" if negrita else "normal")


def fuente_canvas(tamanio: int = 10) -> tuple:
    """Fuente para textos dibujados en un tk.Canvas."""
    return (FUENTE, tamanio)
