import ttkbootstrap as ttk
from interfaz import AntivirusGUI
from antivirus import logger

if __name__ == "__main__":
    app = ttk.Window(themename="darkly", title="Antivirus Beta", size=(700, 550)) # No coge el tema por defecto del sistema
    gui = AntivirusGUI(app)
    app.mainloop() # Lanza la GUI explícitamente
