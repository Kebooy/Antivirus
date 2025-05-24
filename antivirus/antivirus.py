import wmi      # Para interactuar con WMI en Windows
import os       # Operaciones con el sistema de archivos
import ctypes   # Para comprobar privilegios de administrador en Windows
import json     # Para que los virus ignorados persistan entre sesiones

from .hash_analyzer import HashAnalyzer
from .heuristic_analyzer import HeuristicAnalyzer
from .virustotal_scanner import VirusTotalScanner
from .quarantine_manager import QuarantineManager
from .logger import Logger
from database.hash_db import HashDB

# DUDAS
# vt_client: Es el objeto que usamos para conectarnos a VirusTotal
# vt.Client: Es la clase que proporciona VirusTotal para crear ese cliente
# hexdigest(): Convierte un hash (que es binario) a un texto legible con letras y números
# self.vt_client.get_object(...): Con esta función le pedimos a VirusTotal información sobre un archivo (por su hash). Nos devuelve un “informe” con estadísticas sobre ese archivo.
# report.last_analysis_stats.get("malicious", 0): Accede al informe que devuelve VirusTotal y busca cuántos antivirus detectaron ese archivo como peligroso. Si no encuentra el dato, devuelve 0.
# os.path.basename(archivo): Saca solo el nombre del archivo, sin la ruta. Por ejemplo, si el archivo está en C:/algo/malware.exe, esto devuelve solo malware.exe.
# os.path.join(...): Une correctamente partes de rutas del sistema operativo. Así se forma una ruta válida como cuarentena/malware.exe, sin errores por las barras (/, \).
# for raiz, _, archivos in os.walk(directorio): : Recorre todas las carpetas y subcarpetas dentro del directorio que queremos escanear. archivos contiene la lista de archivos en cada carpeta
# for proceso in self.wmi_client.Win32_Process.watch_for("creation"): : Espera a que se cree un nuevo proceso en el sistema. En cuanto eso pasa, el antivirus puede analizarlo en tiempo real.
# ruta = proceso.ExecutablePath: Obtiene la ruta completa del archivo ejecutable que inició el proceso.
# is_admin = os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin(): Comprueba si el programa se está ejecutando como administrador en Windows.
# os.chmod(path, stat.S_IREAD): Cambia los permisos de una carpeta o archivo para que sea solo de lectura.
# mostrar_func=None: si al crear el obj no le paso un argumento para mostrar_func su valor sera none


class Antivirus:
    def __init__(self, mostrar_func=None):
        """
        Inicializa la clase Antivirus.
        - Configura la clave API de VirusTotal.
        - Carga los hashes de malware conocidos.
        - Crea la carpeta de cuarentena para aislar los archivos maliciosos.
        Si no tengo ninguna función para mostrar mensajes, uso print por defecto.
        """
        if mostrar_func is None:
            self.mostrar_func = print
        else:
            self.mostrar_func = mostrar_func
        self.logger = Logger()
        self.hash_analyzer = HashAnalyzer()
        self.heuristic = HeuristicAnalyzer()
        self.virustotal = VirusTotalScanner("6370218ae16f433996cf763f16ae4b5227cf7b7a14e1ce196bb96acfcc6b65d4")
        self.quarantine = QuarantineManager()
        self.logger = Logger()
        self.db = HashDB()
        self.wmi_client = wmi.WMI()
        self.archivo_ignorados = "ignorados.json"
        self.cargar_ignorados()

    def log(self, mensaje):
        self.log_func(mensaje)

    def guardar_ignorados(self):
        """
        Guardo los archivos que han sido ignorados en un json para poder cargarlos después.
        Con esto hago que estos archivos persistan entre sesiones.
        """
        try:
            with open(self.archivo_ignorados, "w") as f:
                json.dump(list(self.virus_ignorados), f)
        except Exception as e:
            self.log(f"Error al guardar virus ignorados: {e}")

    def cargar_ignorados(self):
        """
        Cargo los archivos ignorados desde el json para no volver a detectarlos.
        """
        try:
            with open(self.archivo_ignorados, "r") as f:
                self.virus_ignorados = set(json.load(f))
        except FileNotFoundError:
            self.virus_ignorados = set()
        except Exception as e:
            self.log(f"Error al cargar ignorados: {e}")
            self.virus_ignorados = set()

    def analizar_archivo(self, archivo):
        """
        Analiza un único archivo en busca de malware.
        - Primero calcula su hash y lo compara con los hashes conocidos.
        - Luego realiza un análisis heurístico buscando patrones sospechosos.
        - Finalmente, consulta VirusTotal para obtener más información.
        """
        hash_archivo = self.hash_analyzer.calcular_hash(archivo)
        if not hash_archivo or hash_archivo in self.virus_ignorados:
            return

        accion_requerida = None

        if hash_archivo in self.hash_analyzer.hashes_maliciosos:
            self.log(f"⚠️ ¡ALERTA! {archivo} es un malware conocido localmente")
            accion_requerida = "local"
        elif self.heuristic.heuristica_archivo(archivo):
            self.log(f"⚠️ ¡ALERTA! {archivo} muestra comportamiento sospechoso por heurística")
            accion_requerida = "heurística"
        elif self.virustotal.consultar_virustotal(hash_archivo):
            self.log(f"⚠️ ¡ALERTA! {archivo} detectado como malicioso por VirusTotal")
            accion_requerida = "virustotal"

        if accion_requerida:
            self.log(f"\n🔎 Se ha detectado una amenaza por {accion_requerida}. ¿Qué deseas hacer con '{archivo}'?")
            self.log("1. 🛑 Mover a cuarentena")
            self.log("2. ❌ Eliminar archivo")
            self.log("3. ✅ Ignorar (no volver a detectar este archivo)")

            opcion = input("Selecciona una opción (1, 2 o 3): ").strip()

            if opcion == "1":
                self.quarantine.mover_a_cuarentena(archivo)
                self.quarantine.proteger_directorio(self.quarantine.carpeta)
                self.logger.registrar_log(archivo, accion_requerida, "cuarentena")
            elif opcion == "2":
                try:
                    os.remove(archivo)
                    self.log(f"❌ Archivo eliminado: {archivo}")
                    self.logger.registrar_log(archivo, accion_requerida, "eliminado")
                except Exception as e:
                    self.log(f"Error al eliminar archivo: {e}")
            elif opcion == "3":
                self.virus_ignorados.add(hash_archivo)
                self.guardar_ignorados()
                self.log(f"🟢 El archivo ha sido ignorado. No se volverá a marcar como amenaza.")
                self.logger.registrar_log(archivo, accion_requerida, "ignorado")

            else:
                self.log("⚠️ Opción no válida. No se realizó ninguna acción.")
        else:
            self.log(f"✅ {archivo} parece seguro.")

    def analizar_directorio(self, directorio):
        """
        Recorre un directorio y analiza todos los archivos que contiene.
        Esto es útil para hacer escaneos completos.
        """
        self.log(f"🔍 Escaneando el directorio: {directorio}")
        for raiz, _, archivos in os.walk(directorio):
            for archivo in archivos:
                ruta_completa = os.path.join(raiz, archivo)
                self.analizar_archivo(ruta_completa)

    def monitorear_procesos(self):
        """
        Se usa WMI para observar en tiempo real la creación de nuevos procesos.
        Si se ejecutan desde una ruta sospechosa como Temp o AppData, se muestra una alerta.
        """
        self.log("🔍 Monitoreando procesos en tiempo real...")
        for proceso in self.wmi_client.Win32_Process.watch_for("creation"):
            ruta = proceso.ExecutablePath
            if ruta and ("Temp" in ruta or "AppData" in ruta):
                self.log(f"⚠️ Proceso sospechoso detectado: {proceso.Name} en {ruta}")

    def comprobar_privilegios(self):
        """
        Verifica si el antivirus se ejecuta como administrador.
        Algunos análisis solo pueden realizarse con privilegios de administrador.
        """
        try:
            is_admin = os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                self.log("🔐 Ejecutando como administrador.")
            else:
                self.log("⚠️ No tienes privilegios de administrador.")
            return is_admin
        except:
            self.log("⚠️ No se ha podido comprobar el nivel de privilegios.")
            return False

    def escaneo_rapido(self):
        """
        Realiza un escaneo rápido solo en directorios comunes donde suele ocultarse el malware.
        """
        self.mostrar_func("Iniciando escaneo rápido...")
        rutas_comunes = [
            os.path.expanduser("~/Escritorio"),
            os.path.expanduser("~/Descargas"),
            os.path.expanduser("~/Documentos"),
            os.environ.get("TEMP", ""),
            os.path.expandvars(r"%APPDATA%"),
        ]

        self.log("Inicio de escaneo rápido")
        for ruta in rutas_comunes:
            if ruta and os.path.exists(ruta):
                self.analizar_directorio(ruta)
            else:
                self.log(f"⚠️ Ruta no válida o no encontrada: {ruta}")

    def escaneo_completo(self):
        """
        Realiza un escaneo completo del sistema recorriendo todo el disco.
        """
        self.mostrar_func("Iniciando escaneo completo...")
        if os.name == "nt":
            unidad = "C:\\" # Windows
        else:
            unidad = "/"  # UNIX/Linux

        self.log("Inicio de escaneo completo")
        self.analizar_directorio(unidad)
