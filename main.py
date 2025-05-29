import ttkbootstrap as ttk
from interfaz import AntivirusGUI

if __name__ == "__main__":
    app = ttk.Window(title="Antivirus", size=(900, 600))
    gui = AntivirusGUI(app)
    app.mainloop() # Lanza la GUI explícitamente