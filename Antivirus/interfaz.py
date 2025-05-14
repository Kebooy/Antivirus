import tkinter as tk
from tkinter import scrolledtext, messagebox
from antivirus import Antivirus
import threading  # Para que los escaneos no congelen la interfaz


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Beta")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Instancia del antivirus
        self.antivirus = Antivirus()

        # Redirigir print al área de texto
        self.original_print = print
        self.redirigir_print()

        # Botones
        tk.Button(root, text="Escaneo Rápido", width=20, command=self.hilo_escanear_rapido).pack(pady=10)
        tk.Button(root, text="Escaneo Completo", width=20, command=self.hilo_escanear_completo).pack(pady=10)

        # Área de texto
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=80)
        self.text_area.pack(padx=10, pady=10)

        # Comprobar privilegios al iniciar
        self.antivirus.comprobar_privilegios()

    def mostrar_mensaje(self, texto):
        self.salida_texto.configure(state='normal')
        self.salida_texto.insert(tk.END, texto + "\n")
        self.salida_texto.see(tk.END)
        self.salida_texto.configure(state='disabled')


    def redirigir_print(self):
        def print_gui(*args, **kwargs):
            texto = ' '.join(map(str, args)) + '\n'
            self.text_area.insert(tk.END, texto)
            self.text_area.see(tk.END)
            self.original_print(*args, **kwargs)
        globals()['print'] = print_gui  # Redefinir print global

    def hilo_escanear_rapido(self):
        threading.Thread(target=self.antivirus.escanear_rapido, daemon=True).start()

    def hilo_escanear_completo(self):
        respuesta = messagebox.askyesno("Confirmar escaneo completo", "Esto puede tardar bastante. ¿Estás seguro?")
        if respuesta:
            threading.Thread(target=self.antivirus.escanear_completo, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()
