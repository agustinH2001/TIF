"""Pantalla de historial: resumen del período, movimientos por día, tabla paginada y exportación."""

import csv
import math
import tkinter as tk
from datetime import date, datetime, timedelta
from tkinter import filedialog
from typing import Optional

import customtkinter as ctk

from src.database.database import (
    contar_eventos_usuario,
    obtener_estadisticas_periodo,
    obtener_historico_usuario,
    obtener_resumen_diario,
)
from src.ui.componentes import (
    boton, cifra, en_hilo, etiqueta, formatear_dia, formatear_duracion, icono, panel,
)
from src.ui.tema import COLORES, MARGEN, fuente, fuente_canvas

EVENTOS_POR_PAGINA = 10
# Período -> cantidad de días (None = sin límite)
PERIODOS = {"Hoy": 1, "7 días": 7, "30 días": 30, "Todo": None}
COLUMNAS = [("Fecha", 130), ("Inicio", 100), ("Fin", 100), ("Duración", 110), ("Intensidad", 110)]


def _numero_csv(valor: Optional[float], decimales: int) -> str:
    """Número con coma decimal, para que Excel en español lo lea como número."""
    return "" if valor is None else f"{valor:.{decimales}f}".replace(".", ",")


class PantallaHistorial(ctk.CTkScrollableFrame):
    def __init__(self, master, usuario_id: int):
        super().__init__(master, fg_color="transparent")
        self.usuario_id = usuario_id
        self.periodo = "7 días"
        self.pagina = 0
        self._id_consulta = 0
        self._barras: list = []
        self._resumen_diario: list = []
        self._dias_grafico = 7
        self.grid_columnconfigure(0, weight=1)

        # Filtros
        filtros = ctk.CTkFrame(self, fg_color="transparent")
        filtros.grid(row=0, column=0, sticky="ew", padx=MARGEN - 6)
        filtros.grid_columnconfigure(1, weight=1)
        self.selector = ctk.CTkSegmentedButton(
            filtros, values=list(PERIODOS), font=fuente(13), height=34, command=self._on_periodo,
            selected_color=COLORES["boton"], selected_hover_color=COLORES["boton_hover"],
            unselected_color=COLORES["superficie"], unselected_hover_color=COLORES["superficie_alta"],
            fg_color=COLORES["superficie"],
        )
        self.selector.set(self.periodo)
        self.selector.grid(row=0, column=0, sticky="w")
        self.label_estado = etiqueta(filtros, "", 12, suave=True)
        self.label_estado.grid(row=0, column=1, sticky="e", padx=12)
        self.boton_exportar = boton(filtros, "Exportar CSV", primario=False, width=140,
                                    image=icono("exportar_activo", 16), compound="left",
                                    command=self._exportar)
        self.boton_exportar.grid(row=0, column=2)

        # Resumen
        resumen = ctk.CTkFrame(self, fg_color="transparent")
        resumen.grid(row=1, column=0, sticky="ew", padx=MARGEN - 6, pady=(16, 10))
        self.cifras = {}
        for columna, (clave, descripcion) in enumerate([
            ("cantidad", "movimientos"), ("duracion_total", "en movimiento"),
            ("duracion_promedio", "duración promedio"), ("varianza_pico", "intensidad máxima"),
        ]):
            marco, self.cifras[clave] = cifra(resumen, "—", descripcion, tamanio=20)
            marco.grid(row=0, column=columna, sticky="w", padx=(0, 46))

        # Gráfico
        grafico = panel(self)
        grafico.grid(row=2, column=0, sticky="ew", padx=MARGEN - 6)
        grafico.grid_columnconfigure(0, weight=1)
        self.label_grafico = etiqueta(grafico, "Movimientos por día", 14, negrita=True)
        self.label_grafico.grid(row=0, column=0, sticky="w", padx=22, pady=(14, 0))
        self.canvas = tk.Canvas(grafico, height=130, bg=COLORES["superficie"], highlightthickness=0)
        self.canvas.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 14))
        self.canvas.bind("<Configure>", lambda _e: self._dibujar_grafico())
        self.canvas.bind("<Motion>", self._on_mouse)
        self.canvas.bind("<Leave>", lambda _e: self._ocultar_tooltip())

        # Tabla
        self.tabla = panel(self)
        self.tabla.grid(row=3, column=0, sticky="ew", padx=MARGEN - 6, pady=14)
        self.tabla.grid_columnconfigure(0, weight=1)
        self._fila_tabla(0, [t for t, _ in COLUMNAS], encabezado=True)
        ctk.CTkFrame(self.tabla, height=1, fg_color=COLORES["linea"]).grid(row=1, column=0, sticky="ew", padx=14)
        self.filas = [self._fila_tabla(r + 2, [""] * len(COLUMNAS)) for r in range(EVENTOS_POR_PAGINA)]
        self.label_vacio = etiqueta(self.tabla, "", suave=True)
        self.label_vacio.grid(row=EVENTOS_POR_PAGINA + 2, column=0, pady=(6, 0))
        pie = ctk.CTkFrame(self.tabla, fg_color="transparent")
        pie.grid(row=EVENTOS_POR_PAGINA + 3, column=0, sticky="ew", padx=22, pady=(10, 14))
        pie.grid_columnconfigure(0, weight=1)
        self.label_pagina = etiqueta(pie, "", 12, suave=True)
        self.label_pagina.grid(row=0, column=0, sticky="w")
        self.boton_anterior = boton(pie, "Anterior", primario=False, width=90, command=lambda: self._pagina(-1))
        self.boton_anterior.grid(row=0, column=1, padx=6)
        self.boton_siguiente = boton(pie, "Siguiente", primario=False, width=90, command=lambda: self._pagina(1))
        self.boton_siguiente.grid(row=0, column=2)

        self.actualizar()

    def _fila_tabla(self, fila: int, textos: list, encabezado: bool = False):
        marco = ctk.CTkFrame(self.tabla, fg_color="transparent", corner_radius=6, height=32)
        marco.grid(row=fila, column=0, sticky="ew", padx=12, pady=1)
        celdas = []
        for columna, (texto, (_, ancho)) in enumerate(zip(textos, COLUMNAS)):
            marco.grid_columnconfigure(columna, weight=1, minsize=ancho, uniform="columna")
            celda = ctk.CTkLabel(marco, text=texto, anchor="w", font=fuente(12 if encabezado else 13, encabezado),
                                 text_color=COLORES["texto_suave"] if encabezado else COLORES["texto"])
            celda.grid(row=0, column=columna, sticky="ew", padx=10, pady=3)
            celdas.append(celda)
        return marco, celdas

    # -- Consultas -------------------------------------------------------------
    def _desde(self) -> Optional[date]:
        dias = PERIODOS[self.periodo]
        return date.today() - timedelta(days=dias - 1) if dias else None

    def _on_periodo(self, periodo: str) -> None:
        self.periodo = periodo
        self.pagina = 0
        self.actualizar()

    def _pagina(self, delta: int) -> None:
        self.pagina += delta
        self.actualizar()

    def actualizar(self) -> None:
        self._id_consulta += 1
        id_consulta = self._id_consulta
        self.label_estado.configure(text="Cargando...")
        desde, pagina = self._desde(), self.pagina
        dias = PERIODOS[self.periodo]
        dias_grafico = 30 if dias is None or dias > 7 else 7

        def consultar():
            return {
                "estadisticas": obtener_estadisticas_periodo(self.usuario_id, desde=desde),
                "total": contar_eventos_usuario(self.usuario_id, desde=desde),
                "eventos": obtener_historico_usuario(
                    self.usuario_id, limite=EVENTOS_POR_PAGINA,
                    desplazamiento=pagina * EVENTOS_POR_PAGINA, desde=desde),
                "resumen_diario": obtener_resumen_diario(self.usuario_id, dias=dias_grafico),
                "dias_grafico": dias_grafico,
            }

        en_hilo(self, consultar, lambda datos: self._mostrar(id_consulta, datos))

    # -- Presentación ----------------------------------------------------------
    def _mostrar(self, id_consulta: int, datos: Optional[dict]) -> None:
        if id_consulta != self._id_consulta:
            return
        if datos is None:
            self.label_estado.configure(text="No se pudo consultar la base de datos.", text_color=COLORES["error"])
            return
        self.label_estado.configure(text=f"Actualizado {datetime.now():%H:%M:%S}", text_color=COLORES["texto_suave"])

        est = datos["estadisticas"]
        self.cifras["cantidad"].configure(text=str(est["cantidad"]))
        self.cifras["duracion_total"].configure(text=formatear_duracion(est["duracion_total"]))
        self.cifras["duracion_promedio"].configure(
            text=formatear_duracion(est["duracion_promedio"]) if est["cantidad"] else "—")
        self.cifras["varianza_pico"].configure(
            text="—" if est["varianza_pico"] is None else f"{est['varianza_pico']:.2f}")

        self._resumen_diario = datos["resumen_diario"]
        self._dias_grafico = datos["dias_grafico"]
        self.label_grafico.configure(text=f"Movimientos por día, últimos {self._dias_grafico} días")
        self._dibujar_grafico()

        total = datos["total"]
        paginas = max(1, math.ceil(total / EVENTOS_POR_PAGINA))
        if self.pagina >= paginas:
            self.pagina = paginas - 1
            self.actualizar()
            return
        self._llenar_tabla(datos["eventos"])
        primero = self.pagina * EVENTOS_POR_PAGINA + 1
        ultimo = primero + len(datos["eventos"]) - 1
        self.label_pagina.configure(text=f"Mostrando {primero} a {ultimo} de {total}" if total else "")
        self.boton_anterior.configure(state="normal" if self.pagina > 0 else "disabled")
        self.boton_siguiente.configure(state="normal" if self.pagina < paginas - 1 else "disabled")

    def _llenar_tabla(self, eventos: list) -> None:
        for indice, (marco, celdas) in enumerate(self.filas):
            if indice < len(eventos):
                evento = eventos[indice]
                fin = evento["timestamp_fin"]
                textos = [
                    formatear_dia(evento["timestamp"].date()),
                    f"{evento['timestamp']:%H:%M:%S}",
                    f"{fin:%H:%M:%S}" if fin else "En curso",
                    formatear_duracion(evento["duracion_segundos"]) if fin else "",
                    "—" if evento["varianza_maxima"] is None else f"{evento['varianza_maxima']:.2f}",
                ]
                fondo = COLORES["superficie_alta"] if indice % 2 else "transparent"
            else:
                textos, fondo = [""] * len(COLUMNAS), "transparent"
            marco.configure(fg_color=fondo)
            for columna, (celda, texto) in enumerate(zip(celdas, textos)):
                en_curso = columna == 2 and texto == "En curso"
                celda.configure(text=texto, text_color=COLORES["movimiento"] if en_curso else COLORES["texto"])
        self.label_vacio.configure(text="" if eventos else "No hay movimientos en este período.")

    def _dibujar_grafico(self) -> None:
        c = self.canvas
        c.delete("all")
        ancho, alto = max(c.winfo_width(), 200), int(c.cget("height"))
        izq, abajo, arriba = 28, 22, 14
        hoy = date.today()
        por_dia = {fila["fecha"]: fila for fila in self._resumen_diario}
        dias = [hoy - timedelta(days=i) for i in range(self._dias_grafico - 1, -1, -1)]
        cantidades = [int(por_dia[d]["cantidad"]) if d in por_dia else 0 for d in dias]
        maximo = max(cantidades + [1])
        paso = max(1, math.ceil(maximo / 2))
        tope = paso * math.ceil(maximo / paso)

        def y_de(valor: float) -> float:
            return alto - abajo - (alto - abajo - arriba) * valor / tope

        for valor in range(0, tope + 1, paso):
            c.create_line(izq, y_de(valor), ancho, y_de(valor), fill=COLORES["superficie_alta"])
            c.create_text(izq - 8, y_de(valor), text=str(valor), anchor="e",
                          fill=COLORES["texto_suave"], font=fuente_canvas())

        slot = (ancho - izq) / len(dias)
        media_barra = slot * 0.22 if len(dias) <= 7 else max(slot / 2 - 1, 1)
        cada = 1 if len(dias) <= 7 else 5
        indice_max = cantidades.index(max(cantidades))
        self._barras = []
        for i, (dia, cantidad) in enumerate(zip(dias, cantidades)):
            centro = izq + slot * (i + 0.5)
            if cantidad:
                c.create_rectangle(centro - media_barra, y_de(cantidad), centro + media_barra, y_de(0),
                                   fill=COLORES["senal"], outline="")
            if i == indice_max and cantidad:
                c.create_text(centro, y_de(cantidad) - 8, text=str(cantidad), fill=COLORES["texto"],
                              font=fuente_canvas(), tags="etiqueta_maximo")
            if (len(dias) - 1 - i) % cada == 0:
                c.create_text(centro, alto - 8, text=formatear_dia(dia, corto=True),
                              fill=COLORES["texto_suave"], font=fuente_canvas())
            fila = por_dia.get(dia)
            self._barras.append((izq + slot * i, izq + slot * (i + 1), dia, cantidad,
                                 float(fila["duracion_total"]) if fila else 0.0))

    def _ocultar_tooltip(self) -> None:
        self.canvas.delete("tooltip")
        self.canvas.itemconfigure("etiqueta_maximo", state="normal")

    def _on_mouse(self, evento) -> None:
        self._ocultar_tooltip()
        for x0, x1, dia, cantidad, duracion in self._barras:
            if x0 <= evento.x < x1:
                texto = f"{formatear_dia(dia)}: {cantidad} movimiento{'s' if cantidad != 1 else ''}"
                if cantidad:
                    texto += f", {formatear_duracion(duracion)}"
                ancla = "e" if evento.x > self.canvas.winfo_width() * 0.6 else "w"
                item = self.canvas.create_text(evento.x + (-12 if ancla == "e" else 12), 12, text=texto,
                                               anchor=ancla, fill=COLORES["texto"],
                                               font=fuente_canvas(11), tags="tooltip")
                xa, ya, xb, yb = self.canvas.bbox(item)
                fondo = self.canvas.create_rectangle(xa - 8, ya - 4, xb + 8, yb + 4, fill=COLORES["superficie_alta"],
                                                     outline=COLORES["linea"], tags="tooltip")
                self.canvas.tag_raise(item, fondo)
                self.canvas.itemconfigure("etiqueta_maximo", state="hidden")
                break

    # -- Exportación -----------------------------------------------------------
    def _exportar(self) -> None:
        sufijo = {"Hoy": "hoy", "7 días": "7dias", "30 días": "30dias", "Todo": "completo"}[self.periodo]
        ruta = filedialog.asksaveasfilename(
            title="Exportar historial", defaultextension=".csv",
            initialfile=f"movimientos_{sufijo}_{date.today():%Y%m%d}.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not ruta:
            return
        self.boton_exportar.configure(state="disabled", text="Exportando...")
        desde = self._desde()
        en_hilo(self, lambda: self._escribir_csv(ruta, desde), self._exportacion_terminada)

    def _escribir_csv(self, ruta: str, desde: Optional[date]) -> int:
        eventos = obtener_historico_usuario(self.usuario_id, desde=desde)
        # Separador ';' y BOM UTF-8: Excel en español lo abre en columnas y con acentos correctos
        with open(ruta, "w", newline="", encoding="utf-8-sig") as archivo:
            escritor = csv.writer(archivo, delimiter=";")
            escritor.writerow(["id", "fecha", "inicio", "fin", "duracion_s", "intensidad_maxima"])
            for e in eventos:
                escritor.writerow([
                    e["id"], f"{e['timestamp']:%d/%m/%Y}", f"{e['timestamp']:%H:%M:%S}",
                    f"{e['timestamp_fin']:%H:%M:%S}" if e["timestamp_fin"] else "",
                    _numero_csv(e["duracion_segundos"], 1), _numero_csv(e["varianza_maxima"], 4),
                ])
        return len(eventos)

    def _exportacion_terminada(self, cantidad: Optional[int]) -> None:
        self.boton_exportar.configure(state="normal", text="Exportar CSV")
        if cantidad is None:
            self.label_estado.configure(text="No se pudo exportar el archivo.", text_color=COLORES["error"])
        else:
            self.label_estado.configure(text=f"Exportados {cantidad} movimientos.", text_color=COLORES["ok"])

    def detener(self) -> None:
        pass
