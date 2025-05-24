import os # Operaciones con el sistema de archivos
import shutil # Para mover archivos (poner en cuarentena)
import stat # Para cambiar permisos de archivos y directorios
from logger import Logger

class QuarantineManager:
    def __init__(self, carpeta="cuarentena"):
        self.carpeta = carpeta
        os.makedirs(self.carpeta, exist_ok=True)
        self.logger = Logger()

    def mover_a_cuarentena(self, archivo):
        """
        Mueve archivos detectados como peligrosos a la carpeta de cuarentena.
        Sirve como medida preventiva para evitar su ejecución o propagación.
        """
        try:
            nombre_archivo = os.path.basename(archivo)
            destino = os.path.join(self.carpeta, nombre_archivo)
            shutil.move(archivo, destino)
            self.logger.log(f"🛑 Archivo movido a cuarentena: {destino}")
        except Exception as e:
            self.logger.log(f"Error al mover a cuarentena: {e}")

    def proteger_directorio(self, path):
        """
        Intenta proteger un directorio haciéndolo de solo lectura.
        Esto impide que algún malware escriba o modifique contenido importante.
        """
        try:
            os.chmod(path, stat.S_IREAD)
            self.logger.log(f"🛡️ Directorio protegido: {path}")
        except Exception as e:
            self.logger.log(f"Error al proteger el directorio: {e}")