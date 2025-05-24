from datetime import datetime

class Logger:
    def __init__(self, archivo_log="registro_actividad.log"):
        self.archivo_log = archivo_log

    def registrar_log(self, ruta_archivo, tipo_deteccion, accion):
        """
        Registra eventos relacionados con acciones del antivirus sobre archivos.
        :param ruta_archivo:
        :param tipo_deteccion:
        :param accion:
        :return:
        """
        try:
            fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("registro_actividad.log", "a") as f:
                f.write(f"[{fecha_hora}] {ruta_archivo} | Detección: {tipo_deteccion} | Acción: {accion}\n")
        except Exception as e:
            print(f"Error al registrar log: {e}")

    def log(self, mensaje):
        """
        Método genérico para registrar cualquier mensaje en el log, añadiendo la fecha y hora.
        :param mensaje:
        :return:
        """
        fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        linea = f"[{fecha_hora}] {mensaje}"
        try:
            with open(self.archivo_log, "a", encoding="utf-8") as f:
                f.write(linea + "\n")
        except Exception as e:
            # Solo imprime errores graves del logger
            print(f"[Logger] Error al escribir en el log: {e}")