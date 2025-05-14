import tkinter as tk
from interfaz import AntivirusGUI
from antivirus import Antivirus

if __name__ == "__main__":
    antivirus = Antivirus()
    antivirus.comprobar_privilegios()

    # Escaneo rápido
    # antivirus.escanear_rapido()

    # Escaneo completo
    # antivirus.escanear_completo()
