import concurrent

import wmi      # Para interactuar con WMI en Windows
import os       # Operaciones con el sistema de archivos
import ctypes   # Para comprobar privilegios de administrador en Windows
import json     # Para que los virus ignorados persistan entre sesiones

from antivirus.hash_analyzer import HashAnalyzer
from antivirus.heuristic_analyzer import HeuristicAnalyzer
from antivirus.virustotal_scanner import VirusTotalScanner
from antivirus.quarantine_manager import QuarantineManager
from antivirus.logger import Logger
from database.hash_db import HashDB
from dotenv import load_dotenv

load_dotenv() # Carga las variables de entorno desde un archivo .env

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
        self.virustotal = VirusTotalScanner("API_KEY")
        self.quarantine = QuarantineManager()
        self.hash_db = HashDB()
        self.wmi_client = wmi.WMI()

        # Para almacenar los hashes de virus ignorados
        self.archivo_ignorados = "ignorados.json"
        self.cargar_ignorados()

        self.detener = False # Para detener los escaneos

        # Para reanudar los escaneos
        self.estado_guardado = "estado_escaneo.json"
        self.escaneo_pendiente = None
        self.ultima_ruta = None
        self.tipo_escaneo = None
        self.cargar_estado_escaneo()

    def log(self, mensaje):
        self.mostrar_func(mensaje)

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

    def guardar_estado_escaneo(self, tipo, ruta):
        estado = {"tipo": tipo, "ruta": ruta}
        with open(self.estado_guardado, "w") as estado_file:
            json.dump(estado, estado_file)

    def cargar_estado_escaneo(self):
        try:
            with open(self.estado_guardado, "r") as estado_file:
                estado = json.load(estado_file)
                self.escaneo_pendiente = True
                self.tipo_escaneo = estado.get("tipo")
                self.ultima_ruta = estado.get("ruta")
        except:
            self.escaneo_pendiente = False
            self.tipo_escaneo = None
            self.ultima_ruta = None

    def limpiar_estado_escaneo(self):
        self.escaneo_pendiente = False
        self.tipo_escaneo = None
        self.ultima_ruta = None
        if os.path.exists(self.estado_guardado):
            os.remove(self.estado_guardado)

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

            opcion = input("Selecciona una opción (1, 2 o 3): ").strip() # strip = trim

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

    def analizar_directorio(self, directorio, reanudar_desde=None, max_hilos=8): # Lo escaneo desde el inicio o desde un punto específico
        """
        Recorre un directorio y analiza todos los archivos que contiene.
        Esto es útil para hacer escaneos completos.
        """
        self.log(f"🔍 Escaneando el directorio: {directorio}")
        continuar = not reanudar_desde # Si no se pasa reanudar_desde, se empieza desde el principio

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_hilos) as executor:
            for raiz, _, archivos in os.walk(directorio): # Recorre recursivamente
                for archivo in archivos:
                    ruta_completa = os.path.join(raiz, archivo)

                    if not continuar:
                        if ruta_completa == reanudar_desde:
                            continuar = True
                        else:
                            continue # Todavía no llegamos al archivo desde donde reanudar

                    if self.detener:
                        self.log(f"⛔ Escaneo detenido en: {ruta_completa}")
                        self.guardar_estado_escaneo(self.tipo_escaneo, ruta_completa)
                        return # Detiene el escaneo

                    executor.submit(self.analizar_archivo, ruta_completa)
                    self.analizar_archivo(ruta_completa)

        self.log(f" Escaneo del directorio: {directorio} finalizado.")

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

    def escaneo_rapido(self, reanudar=False):
        """
        Realiza un escaneo rápido solo en directorios comunes donde suele ocultarse el malware.
        """
        self.mostrar_func("Iniciando escaneo rápido...")
        rutas_comunes = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Documents"),
            os.environ.get("TEMP", ""),
            os.path.expandvars(r"%APPDATA%"),
        ]
        self.tipo_escaneo = "rapido"
        self.log("Inicio de escaneo rápido")

        for ruta in rutas_comunes:

            if self.detener:
                self.mostrar_func("⛔ Se ha detenido el escaneo rápido.")
                self.log("Escaneo rápido detenido.")
                return

            if ruta and os.path.exists(ruta):
                self.analizar_directorio(ruta, reanudar_desde=self.ultima_ruta if reanudar else None, max_hilos=2)
                self.ultima_ruta = None  # solo una vez
            else:
                self.mostrar_func(f"⚠️ Ruta no encontrada: {ruta}")
                self.log(f"No se ha encontrado la ruta {ruta}")

        self.limpiar_estado_escaneo()
        self.mostrar_func("✅ Escaneo rápido finalizado.")
        self.log("Fin de escaneo rápido")

    def escaneo_completo(self, reanudar=False):
        """
        Realiza un escaneo completo del sistema recorriendo todo el disco.
        """
        self.mostrar_func("Iniciando escaneo completo...")
        if os.name == "nt":
            unidad = "C:\\" # Windows
        else:
            unidad = "/"  # UNIX/Linux

        self.log("Inicio de escaneo completo")
        if not os.path.exists(unidad):
            self.mostrar_func(f"Unidad no encontrada: {unidad}")
            self.log(f"Unidad: {unidad} no encontrada")
            return

        reanudar_desde = self.cargar_estado_escaneo("completo") if reanudar else None
        self.analizar_directorio(unidad, reanudar_desde=reanudar_desde)

        self.analizar_directorio(unidad, reanudar_desde=reanudar_desde, max_hilos=8)

        self.analizar_directorio(unidad)
        if self.detener:
            self.mostrar_func("⛔ Se ha detenido el escaneo rápido.")
            self.log("Escaneo completo detenido")
            return
        else:
            self.mostrar_func("✅ Escaneo completo finalizado.")
            self.log("Fin de escaneo completo")
