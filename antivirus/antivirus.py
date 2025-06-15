from datetime import datetime
import wmi
import os
import ctypes
import json
from antivirus.hash_analyzer import HashAnalyzer
from antivirus.heuristic_analyzer import HeuristicAnalyzer
from antivirus.virustotal_scanner import VirusTotalScanner
from antivirus.quarantine_manager import QuarantineManager
from antivirus.logger import Logger
from database.hash_db import HashDB
from dotenv import load_dotenv

load_dotenv()

class Antivirus:
    def __init__(self, mostrar_func=None, gui=None):
        if mostrar_func is None:
            self.mostrar_func = print
        else:
            self.mostrar_func = mostrar_func

        self.logger = Logger()
        self.hash_analyzer = HashAnalyzer()
        self.heuristic = HeuristicAnalyzer()
        self.gui = gui
        self.root = gui.root if gui else None

        api_key = os.getenv("API_KEY")
        if not api_key or len(api_key) < 32:
            raise ValueError("❌ API_KEY de VirusTotal no válida o no encontrada en el archivo .env")

        self.virustotal = VirusTotalScanner(api_key)
        self.quarantine = QuarantineManager()
        self.hash_db = HashDB()
        self.wmi_client = wmi.WMI()

        self.archivo_ignorados = "ignorados.json"
        self.cargar_ignorados()

        # Control de escaneo mejorado
        self.detener = False
        self.estado_escaneo_file = "estado_escaneo.json"
        self.escaneo_activo = False
        self.ultimo_directorio = None
        self.ultimo_archivo = None
        self.directorios_pendientes = []
        self.tipo_escaneo_actual = None
        self.rutas_rapido = []  # Rutas específicas para escaneo rápido
        self.ruta_actual_index = 0  # Índice de la ruta actual en escaneo rápido

    def log(self, mensaje):
        self.mostrar_func(mensaje)

    def guardar_ignorados(self):
        try:
            with open(self.archivo_ignorados, "w") as f:
                json.dump(list(self.virus_ignorados), f)
        except Exception as e:
            self.log(f"Error al guardar virus ignorados: {e}")

    def cargar_ignorados(self):
        try:
            with open(self.archivo_ignorados, "r") as f:
                self.virus_ignorados = set(json.load(f))
        except FileNotFoundError:
            self.virus_ignorados = set()
        except Exception as e:
            self.log(f"Error al cargar ignorados: {e}")
            self.virus_ignorados = set()

    def guardar_estado_escaneo(self):
        estado = {
            'tipo_escaneo': self.tipo_escaneo_actual,
            'ultimo_directorio': self.ultimo_directorio,
            'ultimo_archivo': self.ultimo_archivo,
            'directorios_pendientes': self.directorios_pendientes,
            'rutas_rapido': self.rutas_rapido,
            'ruta_actual_index': self.ruta_actual_index,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.estado_escaneo_file, 'w') as f:
                json.dump(estado, f)
        except Exception as e:
            self.log(f"Error al guardar estado de escaneo: {e}")

    def cargar_estado_escaneo(self):
        try:
            with open(self.estado_escaneo_file, 'r') as f:
                estado = json.load(f)
                self.tipo_escaneo_actual = estado.get('tipo_escaneo')
                self.ultimo_directorio = estado.get('ultimo_directorio')
                self.ultimo_archivo = estado.get('ultimo_archivo')
                self.directorios_pendientes = estado.get('directorios_pendientes', [])
                self.rutas_rapido = estado.get('rutas_rapido', [])
                self.ruta_actual_index = estado.get('ruta_actual_index', 0)
                return True
        except (FileNotFoundError, json.JSONDecodeError):
            return False
        except Exception as e:
            self.log(f"Error al cargar estado de escaneo: {e}")
            return False

    def limpiar_estado_escaneo(self):
        try:
            if os.path.exists(self.estado_escaneo_file):
                os.remove(self.estado_escaneo_file)
        except Exception as e:
            self.log(f"Error al limpiar estado de escaneo: {e}")
        finally:
            self.ultimo_directorio = None
            self.ultimo_archivo = None
            self.directorios_pendientes = []
            self.tipo_escaneo_actual = None
            self.rutas_rapido = []
            self.ruta_actual_index = 0

    def pausar_escaneo(self):
        self.detener = True
        self.guardar_estado_escaneo()
        self.escaneo_activo = False

    def reanudar_escaneo(self):
        if self.cargar_estado_escaneo():
            self.detener = False
            self.escaneo_activo = True
            return True
        return False

    def analizar_archivo(self, archivo):
        try:
            hash_archivo = self.hash_analyzer.calcular_hash(archivo)
            if not hash_archivo:
                self.log(f"❌ No se pudo calcular hash para: {archivo}")
                return

            if hash_archivo in self.virus_ignorados:
                self.log(f"🔇 Archivo ignorado: {archivo}")
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
            else:
                self.log(f"✅ {archivo} parece seguro")

            if accion_requerida and self.gui:
                self.root.after(0, lambda: self.procesar_opcion_con_gui(archivo, accion_requerida))

        except Exception as e:
            self.log(f"❌ Error al analizar {archivo}: {str(e)}")

    def procesar_opcion_con_gui(self, archivo, accion_requerida):
        opcion = self.gui.ventana_opciones_amenaza(archivo, accion_requerida)
        self.procesar_opcion(opcion, archivo, accion_requerida)

    def procesar_opcion(self, opcion, archivo, accion_requerida):
        if opcion == "1":
            self.quarantine.mover_a_cuarentena(archivo)
            self.quarantine.proteger_directorio(self.quarantine.carpeta)
            self.logger.registrar_log(archivo, accion_requerida, "cuarentena")
            self.mostrar_func(f"🛑 Archivo movido a cuarentena: {archivo}")
        elif opcion == "2":
            try:
                os.remove(archivo)
                self.mostrar_func(f"❌ Archivo eliminado: {archivo}")
                self.logger.registrar_log(archivo, accion_requerida, "eliminado")
            except Exception as e:
                self.mostrar_func(f"Error al eliminar archivo: {e}")
        elif opcion == "3":
            hash_archivo = self.hash_analyzer.calcular_hash(archivo)
            self.virus_ignorados.add(hash_archivo)
            self.guardar_ignorados()
            self.mostrar_func("🟢 El archivo ha sido ignorado. No se volverá a marcar como amenaza.")
            self.logger.registrar_log(archivo, accion_requerida, "ignorado")
        else:
            self.mostrar_func("⚠️ Opción no válida. No se realizó ninguna acción.")

    def analizar_directorio(self, directorio, reanudar=False):
        """Versión mejorada con reanudación precisa"""
        self.log(f"🔍 Escaneando el directorio: {directorio}")

        reanudando = reanudar and self.ultimo_archivo is not None
        encontrado_ultimo = not reanudando
        directorio_actual = None

        if reanudando:
            self.log(f"↩ Reanudando desde: {self.ultimo_archivo}")
            dir_base = os.path.dirname(self.ultimo_archivo)

        for raiz, dirs, archivos in os.walk(directorio):
            if self.detener:
                self.ultimo_directorio = raiz
                self.directorios_pendientes = dirs.copy()
                self.guardar_estado_escaneo()
                self.log(f"⏸ Escaneo pausado en directorio: {raiz}")
                return False

            if reanudando and not encontrado_ultimo:
                if raiz == dir_base:
                    encontrado_ultimo = True
                    archivos = [a for a in sorted(archivos)
                                if os.path.join(raiz, a) > self.ultimo_archivo]
                else:
                    continue

            for archivo in sorted(archivos):
                if self.detener:
                    self.ultimo_archivo = os.path.join(raiz, archivo)
                    self.guardar_estado_escaneo()
                    return False

                ruta_completa = os.path.join(raiz, archivo)
                self.ultimo_archivo = ruta_completa
                self.analizar_archivo(ruta_completa)

                if directorio_actual != raiz:
                    directorio_actual = raiz
                    self.ultimo_directorio = raiz
                    self.guardar_estado_escaneo()

        self.ultimo_archivo = None
        self.ultimo_directorio = None
        return True

    def escaneo_rapido(self):
        """Escaneo rápido con reanudación propia"""
        self.tipo_escaneo_actual = 'rapido'
        self.mostrar_func("Iniciando escaneo rápido...")

        self.rutas_rapido = [
            os.path.expanduser("~\Desktop"),
            os.path.expanduser("~\Downloads"),
            os.path.expanduser("~\Documents"),
            os.environ.get("TEMP", ""),
            os.path.expandvars(r"%APPDATA%"),
        ]

        reanudar = self.cargar_estado_escaneo() and self.tipo_escaneo_actual == 'rapido'

        if reanudar:
            self.mostrar_func("↩ Reanudando escaneo rápido desde el último punto...")
            if self.ultimo_directorio:
                try:
                    self.ruta_actual_index = self.rutas_rapido.index(self.ultimo_directorio)
                except ValueError:
                    self.ruta_actual_index = 0
        else:
            self.ruta_actual_index = 0

        self.log("Inicio de escaneo rápido")
        for i in range(self.ruta_actual_index, len(self.rutas_rapido)):
            if self.detener:
                self.ruta_actual_index = i
                self.guardar_estado_escaneo()
                break

            ruta = self.rutas_rapido[i]
            if ruta and os.path.exists(ruta):
                if not self.analizar_directorio(ruta, reanudar=reanudar and i==self.ruta_actual_index):
                    break
                reanudar = False
            else:
                self.log(f"⚠️ Ruta no válida o no encontrada: {ruta}")

        if self.detener:
            self.mostrar_func("⏸ Escaneo rápido pausado.")
        else:
            self.mostrar_func("✅ Escaneo rápido finalizado.")
            self.limpiar_estado_escaneo()
        self.log("Fin de escaneo rápido")

    def escaneo_completo(self):
        """Escaneo completo con reanudación propia"""
        self.tipo_escaneo_actual = 'completo'
        self.mostrar_func("Iniciando escaneo completo...")

        unidad = "C:\\" if os.name == "nt" else "/"

        reanudar = self.cargar_estado_escaneo() and self.tipo_escaneo_actual == 'completo'

        if reanudar:
            self.mostrar_func("↩ Reanudando escaneo completo desde el último punto...")
            if self.ultimo_archivo:
                directorio_inicial = os.path.dirname(self.ultimo_archivo)
            else:
                directorio_inicial = unidad
        else:
            directorio_inicial = unidad

        self.log("Inicio de escaneo completo")
        if not os.path.exists(unidad):
            self.mostrar_func(f"Unidad no encontrada: {unidad}")

        resultado = self.analizar_directorio(directorio_inicial, reanudar=reanudar)

        if self.detener:
            self.mostrar_func("⏸ Escaneo completo pausado.")
        else:
            self.mostrar_func("✅ Escaneo completo finalizado.")
            self.limpiar_estado_escaneo()
        self.log("Fin de escaneo completo")
        return resultado

    def monitorear_procesos(self):
        self.log("🔍 Monitoreando procesos en tiempo real...")
        for proceso in self.wmi_client.Win32_Process.watch_for("creation"):
            ruta = proceso.ExecutablePath
            if ruta and ("Temp" in ruta or "AppData" in ruta):
                self.log(f"⚠️ Proceso sospechoso detectado: {proceso.Name} en {ruta}")

    def comprobar_privilegios(self):
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