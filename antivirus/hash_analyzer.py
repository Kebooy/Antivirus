import hashlib # Para calcular hashes
import os # Operaciones con el sistema de archivos
from logger import Logger

class HashAnalyzer:
    def __init__(self):
        self.logger = Logger()

    def calcular_hash(self, archivo):
        """
        Calcula el hash SHA-256 de un archivo para compararlo con los conocidos.
        Esto permite detectar amenazas ya identificadas por su huella digital.
        """
        sha256 = hashlib.sha256()
        try:
            with open(archivo, "rb") as f:
                while chunk := f.read(4096): # Lee el archivo en bloques de 4KB para no cargarlo todo en memoria
                    sha256.update(chunk) # Vamos actualizando el hash
            return sha256.hexdigest() # Devuelve el hash como una cadena de texto
        except Exception as e:
            self.logger.log(f"Error al leer el archivo {archivo}: {e}")
            return None