import hashlib # Para calcular hashes
from database.hash_db import HashDB
from antivirus.logger import Logger

class HashAnalyzer:
    def __init__(self):
        self.logger = Logger()
        self.hash_db = HashDB()
        self.hashes_maliciosos = self.hash_db.obtener_todos() # Carga los hashes maliciosos al iniciar

    def _cargar_hashes_maliciosos(self):
        """
        Carga los hashes maliciosos desde la base de datos.
        """
        try:
            registros = self.hash_db.obtener_todos()
            return {fila[1] for fila in registros} # Extrae solo el hash de la columna 1
        except Exception as e:
            self.logger.log(f"Error al cargar hashes maliciosos: {e}")
            return set() # Devuelvo un conjunto vacío en caso de error, así la app sigue funcionando

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