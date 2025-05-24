from ttkbootstrap import Frame, Label, Button, ScrolledText, Treeview, Notebook
from ttkbootstrap.constants import *
from antivirus.antivirus import Antivirus
from tkinter import messagebox
import threading # Para ejecutar tareas en segundo plano sin congelar la GUI


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus")
        self.root.resizable(True, True)

        # Instancio a Antivirus y le paso la función mostrar
        self.antivirus = Antivirus(mostrar_func=self.mostrar)

        self.construir_interfaz()
        self.antivirus.comprobar_privilegios()
        self.root.protocol("WM_DELETE_WINDOW", self.cerrar)

    def construir_interfaz(self):
        self.notebook = Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=YES)

        self.construir_tab_principal()
        self.construir_tab_hashes()

    def construir_tab_principal(self):
        tab_principal = Frame(self.notebook, padding=10)
        self.notebook.add(tab_principal, text="Escaneos")

        Label(tab_principal, text="Antivirus Beta", font=("Segoe UI", 20, "bold")).pack(anchor=W)
        Label(tab_principal, text="Protección básica del sistema", font=("Segoe UI", 12)).pack(anchor=W)

        botones = Frame(tab_principal, padding=(0, 10))
        botones.pack(fill=X)

        Button(botones, text="Escaneo Rápido", bootstyle="primary", width=20,
               command=self.hilo_escanear_rapido).pack(side=LEFT, padx=10)

        Button(botones, text="Escaneo Completo", bootstyle="warning", width=20,
               command=self.hilo_escanear_completo).pack(side=LEFT, padx=10)

        salida_frame = Frame(tab_principal)
        salida_frame.pack(fill=BOTH, expand=YES)

        self.text_area = ScrolledText(salida_frame, wrap="word", height=20)
        self.text_area.pack(fill=BOTH, expand=YES)

    def construir_tab_hashes(self):
        tab_hashes = Frame(self.notebook, padding=10)
        self.notebook.add(tab_hashes, text="Hashes Maliciosos")

        self.tree = Treeview(tab_hashes, columns=("Hash", "Fuente", "Fecha"), show='headings', height=15)
        self.tree.heading("Hash", text="Hash")
        self.tree.heading("Fuente", text="Fuente")
        self.tree.heading("Fecha", text="Fecha")
        self.tree.column("Hash", width=300)
        self.tree.column("Fuente", width=100)
        self.tree.column("Fecha", width=150)

        self.tree.pack(fill=BOTH, expand=YES)

        Button(tab_hashes, text="Refrescar", bootstyle="secondary",
               command=self.actualizar_hashes).pack(pady=10)

        self.actualizar_hashes()

    def actualizar_hashes(self):
        for fila in self.tree.get_children():
            self.tree.delete(fila)

        hashes = self.antivirus.hash_db.listar_hashes()
        for hash_valor, fuente, fecha, _ in hashes:
            self.tree.insert("", END, values=(hash_valor, fuente, fecha))

    def mostrar(self, texto):
        """
        Muestro los mensajes en la GUI
        """
        self.text_area.insert("end", texto + "\n")
        self.text_area.see("end")
        # se usa "end" para añadir al final del texto sin sobreescribir lo anterior, si usara 1.0 insertaría el texto al principio y desplazaría el texto existente

    def hilo_escanear_rapido(self):
        threading.Thread(target=self.antivirus.escaneo_rapido, daemon=True).start()

    def hilo_escanear_completo(self):
        respuesta = messagebox.askyesno("Confirmar escaneo completo", "Esto puede tardar bastante. ¿Estás seguro?")
        if respuesta:
            threading.Thread(target=self.antivirus.escaneo_completo, daemon=True).start()

    def cerrar(self):
        globals()['print'] = self.original_print
        self.root.destroy()
