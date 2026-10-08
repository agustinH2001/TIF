"""Pantalla de inicio de sesión y de creación de usuario."""

import math
import tkinter as tk

import customtkinter as ctk

from src.database.database import registrar_usuario, verificar_usuario
from src.ui.componentes import boton, en_hilo, etiqueta, panel
from src.ui.tema import COLORES, fuente

LARGO_MINIMO_USUARIO = 3
LARGO_MINIMO_CONTRASENIA = 6


class PantallaLogin(ctk.CTkFrame):
    """Formulario de ingreso; con 'Crear un usuario nuevo' pasa al modo registro."""

    def __init__(self, master, on_login_exitoso):
        super().__init__(master, fg_color=COLORES["fondo"], corner_radius=0)
        self.on_login_exitoso = on_login_exitoso
        self.modo_registro = False

        caja = panel(self, width=380)
        caja.place(relx=0.5, rely=0.5, anchor="center")

        trazo = tk.Canvas(caja, width=300, height=46, bg=COLORES["superficie"], highlightthickness=0)
        trazo.grid(row=0, column=0, padx=40, pady=(34, 6))
        puntos = []
        for x in range(0, 301, 4):
            y = 23 + 9 * math.sin(x / 18) * math.exp(-((x - 150) / 70) ** 2) + 2 * math.sin(x / 5)
            puntos += [x, y]
        trazo.create_line(*puntos, fill=COLORES["senal"], width=2, smooth=True)

        self.label_titulo = etiqueta(caja, "Detector de movimiento", 24, negrita=True)
        self.label_titulo.grid(row=1, column=0, padx=40)
        self.label_subtitulo = etiqueta(caja, "Ingresá para ver el estado del sensor.", suave=True)
        self.label_subtitulo.grid(row=2, column=0, padx=40, pady=(2, 22))

        estilo_entrada = dict(width=300, height=40, font=fuente(13), corner_radius=8,
                              fg_color=COLORES["fondo"], border_color=COLORES["linea"])
        self.entrada_usuario = ctk.CTkEntry(caja, placeholder_text="Usuario", **estilo_entrada)
        self.entrada_usuario.grid(row=3, column=0, padx=40, pady=6)
        self.entrada_contrasenia = ctk.CTkEntry(caja, placeholder_text="Contraseña", show="•", **estilo_entrada)
        self.entrada_contrasenia.grid(row=4, column=0, padx=40, pady=6)
        self.entrada_repetir = ctk.CTkEntry(caja, placeholder_text="Repetir contraseña", show="•", **estilo_entrada)

        self.check_mostrar = ctk.CTkCheckBox(
            caja, text="Mostrar contraseña", font=fuente(12), text_color=COLORES["texto_suave"],
            border_color=COLORES["linea"], fg_color=COLORES["boton"], checkbox_width=18,
            checkbox_height=18, command=self._alternar_visibilidad,
        )
        self.check_mostrar.grid(row=6, column=0, padx=40, pady=(4, 0), sticky="w")

        self.label_mensaje = etiqueta(caja, "", 12, wraplength=300)
        self.label_mensaje.grid(row=7, column=0, padx=40, pady=(8, 0))

        self.boton_principal = boton(caja, "Ingresar", width=300, command=self._enviar)
        self.boton_principal.grid(row=8, column=0, padx=40, pady=(10, 8))
        self.boton_cambiar_modo = ctk.CTkButton(
            caja, text="Crear un usuario nuevo", font=fuente(12), fg_color="transparent",
            text_color=COLORES["senal"], hover=False, command=self._cambiar_modo,
        )
        self.boton_cambiar_modo.grid(row=9, column=0, pady=(0, 26))

        for entrada in (self.entrada_usuario, self.entrada_contrasenia, self.entrada_repetir):
            entrada.bind("<Return>", lambda _e: self._enviar())
        self.after(100, self.entrada_usuario.focus_set)

    def _alternar_visibilidad(self) -> None:
        caracter = "" if self.check_mostrar.get() else "•"
        self.entrada_contrasenia.configure(show=caracter)
        self.entrada_repetir.configure(show=caracter)

    def _mostrar_mensaje(self, texto: str, error: bool = True) -> None:
        self.label_mensaje.configure(text=texto, text_color=COLORES["error"] if error else COLORES["ok"])

    def _cambiar_modo(self) -> None:
        self.modo_registro = not self.modo_registro
        self._mostrar_mensaje("")
        self.entrada_contrasenia.delete(0, "end")
        self.entrada_repetir.delete(0, "end")
        if self.modo_registro:
            self.label_titulo.configure(text="Crear usuario")
            self.label_subtitulo.configure(text="Elegí un nombre de usuario y una contraseña.")
            self.entrada_repetir.grid(row=5, column=0, padx=40, pady=6)
            self.boton_principal.configure(text="Crear usuario")
            self.boton_cambiar_modo.configure(text="Ya tengo un usuario")
        else:
            self.label_titulo.configure(text="Detector de movimiento")
            self.label_subtitulo.configure(text="Ingresá para ver el estado del sensor.")
            self.entrada_repetir.grid_remove()
            self.boton_principal.configure(text="Ingresar")
            self.boton_cambiar_modo.configure(text="Crear un usuario nuevo")

    def _enviar(self) -> None:
        usuario = self.entrada_usuario.get().strip()
        contrasenia = self.entrada_contrasenia.get()
        if not usuario or not contrasenia:
            self._mostrar_mensaje("Completá usuario y contraseña.")
            return

        if self.modo_registro:
            if len(usuario) < LARGO_MINIMO_USUARIO:
                self._mostrar_mensaje(f"El usuario debe tener al menos {LARGO_MINIMO_USUARIO} caracteres.")
                return
            if len(contrasenia) < LARGO_MINIMO_CONTRASENIA:
                self._mostrar_mensaje(f"La contraseña debe tener al menos {LARGO_MINIMO_CONTRASENIA} caracteres.")
                return
            if contrasenia != self.entrada_repetir.get():
                self._mostrar_mensaje("Las contraseñas no coinciden.")
                return
            self.boton_principal.configure(state="disabled", text="Creando...")
            en_hilo(self, registrar_usuario, lambda r: self._resultado_registro(r, usuario), usuario, contrasenia)
        else:
            self.boton_principal.configure(state="disabled", text="Verificando...")
            en_hilo(self, verificar_usuario, lambda r: self._resultado_login(r, usuario), usuario, contrasenia)

    def _resultado_login(self, usuario_id, usuario: str) -> None:
        self.boton_principal.configure(state="normal", text="Ingresar")
        if usuario_id is None:
            self._mostrar_mensaje("Usuario o contraseña incorrectos.")
            return
        self.on_login_exitoso(usuario_id, usuario)

    def _resultado_registro(self, usuario_id, usuario: str) -> None:
        self.boton_principal.configure(state="normal", text="Crear usuario")
        if usuario_id is None:
            self._mostrar_mensaje("No se pudo crear el usuario: el nombre ya existe o la base no responde.")
            return
        self._cambiar_modo()
        self.entrada_contrasenia.delete(0, "end")
        self.entrada_repetir.delete(0, "end")
        self._mostrar_mensaje(f"Usuario '{usuario}' creado. Ya podés ingresar.", error=False)
        self.entrada_contrasenia.focus_set()
