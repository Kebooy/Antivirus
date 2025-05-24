from logger import Logger

class HeuristicAnalyzer:
    def __init__(self):
        self.logger = Logger()

    def heuristica_archivo(self, archivo):
        """
        Análisis heurístico:
        Busca patrones de comportamiento sospechoso comunes en malware.
        Compara los patrones byte a byte con el contenido del archivo.
        Detecta si hay más de 3 indicadores maliciosos.
        """
        patrones_sospechosos = [
            b"CreateRemoteThread",   # Inyección de procesos
            b"LoadLibrary",          # Carga de DLLs maliciosas
            b"GetProcAddress",       # Acceso dinámico a funciones del sistema
            b"WinExec",              # Ejecución directa de comandos
            b"keylogger",            # Típico término de malware espía
            b"ransom",               # Típico en ransomware
            b"bitcoin",              # Objetivo económico del ransomware
            b"darknet"               # Indicio de contacto con redes ilegales
        ]

        heuristicas_detectadas = 0

        try:
            with open(archivo, "rb") as f:
                contenido = f.read().lower()  # Se pasa a minúsculas para comparar

                # Cuenta cuántos patrones sospechosos aparecen en el archivo
                for patron in patrones_sospechosos:
                    if patron.lower() in contenido:
                        heuristicas_detectadas += 1

        except Exception as e:
            self.log(f"Error al analizar heurísticamente {archivo}: {e}")
            return False

        # Se considera sospechoso si hay 3 o más coincidencias
        return heuristicas_detectadas >= 3