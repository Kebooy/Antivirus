import csv
import sqlite3
from datetime import datetime

class HashDB:
    def __init__(self, db_path="hashes_maliciosos.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._crear_tabla()
        self._cargar_csv_automatico()

    def _crear_tabla(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE,
                ruta TEXT,
                fecha TEXT
            )
        """)
        self.conn.commit()

    def guardar_hash(self, hash_valor, ruta):
        """
        Guardo un hash malicioso si este no se encuentra en la base de datos
        """
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.cursor.execute("INSERT OR IGNORE INTO hashes (hash, ruta, fecha) VALUES (?, ?, ?)", # Impedir duplicados
                                (hash_valor, ruta, fecha))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Error al guardar hash: {e}")

    def es_malicioso(self, hash_valor):
        """
        Devuelve true si el hash se encuentra en la base de datos
        """
        self.cursor.execute("SELECT 1 FROM hashes WHERE hash = ?", (hash_valor,))
        return self.cursor.fetchone() is not None

    def obtener_todos(self):
        """
        Devuelve una lista de todos los hashes almacenados en la base de datos
        """
        self.cursor.execute("SELECT * FROM hashes")
        return self.cursor.fetchall()

    def _cargar_csv_automatico(self):
        try:
            with open("database/hashes_maliciosos.csv", "r") as f:
                for line in f:
                    if "," in line:
                        hash_valor, ruta = line.strip().split(",", 1)
                        self.guardar_hash(hash_valor, ruta)
        except FileNotFoundError:
            print("No se encontró 'hashes_maliciosos.csv'. La base de datos estará vacía.")

    def obtener_hashes_formateados(self):
        """Devuelve una lista de strings con los hashes y rutas para mostrar en la GUI."""
        self.cursor.execute("SELECT hash, ruta FROM hashes")
        return [f"Hash: {row[0]} | Ruta: {row[1]}" for row in self.cursor.fetchall()]

    def cerrar(self):
        """Cierra la conexión a la base de datos"""
        self.conn.close()
