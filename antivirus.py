from datetime import datetime
import hashlib  # Para calcular hashes
import wmi      # Para interactuar con WMI en Windows
import os       # Operaciones con el sistema de archivos
import shutil   # Para mover archivos (poner en cuarentena)
import ctypes   # Para comprobar privilegios de administrador en Windows
import stat     # Para cambiar permisos de archivos y directorios
import virustotal_python as vt  # Biblioteca oficial de VirusTotal
import json     # Para que los virus ignorados persistan entre sesiones


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


class Antivirus:
    def __init__(self, log_func=None):
        """
        Inicializa la clase Antivirus.
        - Configura la clave API de VirusTotal.
        - Carga los hashes de malware conocidos.
        - Crea la carpeta de cuarentena para aislar los archivos maliciosos.
        - Establece conexión con el cliente WMI.
        """
        self.api_key = "6370218ae16f433996cf763f16ae4b5227cf7b7a14e1ce196bb96acfcc6b65d4" # Clave API de VirusTotal
        self.vt_client = vt.Virustotal(self.api_key)
        self.hashes_maliciosos = {
            "275a021bbfb6485b7cdfb130b0a4b86c",  # Hash de eicar
            "db349b97c37d22f5ea1d1841e3c89eb4"   # Hash de WannaCry
        }
        self.wmi_client = wmi.WMI()  # Inicializa WMI para monitorear procesos
        self.carpeta_cuarentena = "cuarentena"
        os.makedirs(self.carpeta_cuarentena, exist_ok=True)  # Crea la carpeta si no existe
        self.archivo_ignorados = "ignorados.json"
        self.virus_ignorados = set()
        self.cargar_ignorados()
        self.log_func = log_func if log_func else print

    def log(self, mensaje):
        self.log_func(mensaje)

    def registrar_log(self, ruta_archivo, tipo_deteccion, accion):
        try:
            fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("registro_actividad.log", "a") as f:
                f.write(f"[{fecha_hora}] {ruta_archivo} | Detección: {tipo_deteccion} | Acción: {accion}\n")
        except Exception as e:
            print(f"Error al registrar log: {e}")

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
            self.log(f"Error al leer el archivo {archivo}: {e}")
            return None

    def consultar_virustotal(self, hash_archivo):
        """
        Consulta el hash en VirusTotal y devuelve true si hay varios motores que lo detectan como malicioso.
        Esto permite detectar amenazas que no están en la base de datos local.
        Considero que si hay 3 o más motores que lo detectan, es un malware.
        """
        try:
            report = self.vt_client.get_object(f"/files/{hash_archivo}")
            detecciones = report.last_analysis_stats.get("malicious", 0)
            if detecciones >= 3:
                self.log(f"⚠️ VirusTotal detecta {detecciones} motores que han marcado el archivo como malicioso.")
                return True
        except vt.error.APIError as e:
            self.log(f"Error al consultar VirusTotal: {e}")
        except Exception as e:
            self.log(f"Excepción al consultar VirusTotal: {e}")
        return False

    def analizar_archivo(self, archivo):
        """
        Analiza un único archivo en busca de malware.
        - Primero calcula su hash y lo compara con los hashes conocidos.
        - Luego realiza un análisis heurístico buscando patrones sospechosos.
        - Finalmente, consulta VirusTotal para obtener más información.
        """
        hash_archivo = self.calcular_hash(archivo)
        if not hash_archivo or hash_archivo in self.virus_ignorados:
            return

        accion_requerida = None

        if hash_archivo in self.hashes_maliciosos:
            self.log(f"⚠️ ¡ALERTA! {archivo} es un malware conocido localmente")
            accion_requerida = "local"
        elif self.heuristica_archivo(archivo):
            self.log(f"⚠️ ¡ALERTA! {archivo} muestra comportamiento sospechoso por heurística")
            accion_requerida = "heurística"
        elif self.consultar_virustotal(hash_archivo):
            self.log(f"⚠️ ¡ALERTA! {archivo} detectado como malicioso por VirusTotal")
            accion_requerida = "virustotal"

        if accion_requerida:
            self.log(f"\n🔎 Se ha detectado una amenaza por {accion_requerida}. ¿Qué deseas hacer con '{archivo}'?")
            self.log("1. 🛑 Mover a cuarentena")
            self.log("2. ❌ Eliminar archivo")
            self.log("3. ✅ Ignorar (no volver a detectar este archivo)")

            opcion = input("Selecciona una opción (1, 2 o 3): ").strip()

            if opcion == "1":
                self.mover_a_cuarentena(archivo)
                self.proteger_directorio(self.carpeta_cuarentena)
                self.registrar_log(archivo, accion_requerida, "cuarentena")
            elif opcion == "2":
                try:
                    os.remove(archivo)
                    self.log(f"❌ Archivo eliminado: {archivo}")
                    self.registrar_log(archivo, accion_requerida, "eliminado")
                except Exception as e:
                    self.log(f"Error al eliminar archivo: {e}")
            elif opcion == "3":
                self.virus_ignorados.add(hash_archivo)
                self.guardar_ignorados()
                self.log(f"🟢 El archivo ha sido ignorado. No se volverá a marcar como amenaza.")
                self.registrar_log(archivo, accion_requerida, "ignorado")

            else:
                self.log("⚠️ Opción no válida. No se realizó ninguna acción.")
        else:
            self.log(f"✅ {archivo} parece seguro.")

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

    def mover_a_cuarentena(self, archivo):
        """
        Mueve archivos detectados como peligrosos a la carpeta de cuarentena.
        Sirve como medida preventiva para evitar su ejecución o propagación.
        """
        try:
            nombre_archivo = os.path.basename(archivo)
            destino = os.path.join(self.carpeta_cuarentena, nombre_archivo)
            shutil.move(archivo, destino)
            self.log(f"🛑 Archivo movido a cuarentena: {destino}")
        except Exception as e:
            self.log(f"Error al mover a cuarentena: {e}")

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

    def proteger_directorio(self, path):
        """
        Intenta proteger un directorio haciéndolo de solo lectura.
        Esto impide que algún malware escriba o modifique contenido importante.
        """
        try:
            os.chmod(path, stat.S_IREAD)
            self.log(f"🛡️ Directorio protegido: {path}")
        except Exception as e:
            self.log(f"Error al proteger el directorio: {e}")

    def escanear_rapido(self):
        """
        Realiza un escaneo rápido solo en directorios comunes donde suele ocultarse el malware.
        """
        rutas_comunes = [
            os.path.expanduser("~/Escritorio"),
            os.path.expanduser("~/Descargas"),
            os.path.expanduser("~/Documentos"),
            os.environ.get("TEMP", ""),
            os.path.expandvars(r"%APPDATA%"),
        ]

        self.log("🕵️ Iniciando escaneo rápido...")
        for ruta in rutas_comunes:
            if ruta and os.path.exists(ruta):
                self.analizar_directorio(ruta)
            else:
                self.log(f"⚠️ Ruta no válida o no encontrada: {ruta}")

    def escanear_completo(self):
        """
        Realiza un escaneo completo del sistema recorriendo todo el disco.
        """
        if os.name == "nt":
            unidad = "C:\\" # Windows
        else:
            unidad = "/"  # UNIX/Linux

        self.log(f"🕵️ Iniciando escaneo completo en {unidad}...")
        self.analizar_directorio(unidad)


# Pruebas
if __name__ == "__main__":
    antivirus = Antivirus()
    antivirus.comprobar_privilegios()
    antivirus.analizar_directorio("ruta/a/directorio")  # Cambiar por ruta real
    antivirus.monitorear_procesos()
    antivirus.proteger_directorio("ruta/a/proteger")  # Cambiar por ruta real
