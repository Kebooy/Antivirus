from ttkbootstrap import Frame, Label, Button, ScrolledText, Style
from ttkbootstrap.constants import *
from antivirus import Antivirus
from tkinter import messagebox
import threading # Para que los escaneos no congelen la interfaz


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.resizable(False, False)

        self.antivirus = Antivirus()

        self.original_print = print
        self.redirigir_print()

        self.construir_interfaz()

        # Comprobar privilegios al iniciar
        self.antivirus.comprobar_privilegios()

        # Restaurar print al cerrar
        self.root.protocol("WM_DELETE_WINDOW", self.cerrar)

    def construir_interfaz(self):
        # Encabezado
        header = Frame(self.root, padding=(10, 20))
        header.pack(fill=X)

        Label(header, text="Antivirus Beta", font=("Segoe UI", 20, "bold")).pack(anchor=W)
        Label(header, text="Protección básica del sistema", font=("Segoe UI", 12)).pack(anchor=W)

        # Botones
        botones = Frame(self.root, padding=10)
        botones.pack(fill=X)

        Button(botones, text="Escaneo Rápido", bootstyle="primary", width=20,
               command=self.hilo_escanear_rapido).pack(side=LEFT, padx=10)

        Button(botones, text="Escaneo Completo", bootstyle="warning", width=20,
               command=self.hilo_escanear_completo).pack(side=LEFT, padx=10)

        # Área de salida
        salida_frame = Frame(self.root, padding=10)
        salida_frame.pack(fill=BOTH, expand=YES)

        self.text_area = ScrolledText(salida_frame, wrap="word", height=20)
        self.text_area.pack(fill=BOTH, expand=YES)

    def redirigir_print(self):
        def print_gui(*args, **kwargs):
            texto = ' '.join(map(str, args)) + '\n'
            self.text_area.insert("end", texto)
            self.text_area.see("end")
            self.original_print(*args, **kwargs)

        globals()['print'] = print_gui

    def hilo_escanear_rapido(self):
        threading.Thread(target=self.antivirus.escanear_rapido, daemon=True).start()

    def hilo_escanear_completo(self):
        respuesta = messagebox.askyesno("Confirmar escaneo completo", "Esto puede tardar bastante. ¿Estás seguro?")
        if respuesta:
            threading.Thread(target=self.antivirus.escanear_completo, daemon=True).start()

    def cerrar(self):
        globals()['print'] = self.original_print
        self.root.destroy()
