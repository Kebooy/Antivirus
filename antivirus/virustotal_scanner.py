import virustotal_python as vt # Biblioteca oficial de VirusTotal
from virustotal_python import Virustotal
from logger import Logger

class VirusTotalScanner:
    def __init__(self, api_key):
        self.vt = Virustotal(API_KEY=api_key)
        self.logger = Logger()

    def consultar_virustotal(self, hash_archivo):
        """
        Consulta el hash en VirusTotal y devuelve true si hay varios motores que lo detectan como malicioso.
        Esto permite detectar amenazas que no están en la base de datos local.
        Considero que si hay 3 o más motores que lo detectan, es un malware.
        """
        try:
            response = self.vt.request(f"files/{hash_archivo}")
            detecciones = response["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            if detecciones >= 3:
                self.logger.log(f"⚠️ VirusTotal ha detectado {detecciones} motores que han marcado el archivo como malicioso.")
                return True
        except Exception as e:
            self.logger.log(f"❌ Error al consultar VirusTotal: {e}")
        return False