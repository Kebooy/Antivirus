from ttkbootstrap import Style, Frame, Label, Button, ScrolledText, Treeview
from ttkbootstrap.constants import *
from antivirus.antivirus import Antivirus
from tkinter import messagebox, Toplevel
import threading


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus")
        self.root.geometry("900x600")

        # Inicializar estilo (tema)
        self.style = Style(theme='darkly')  # tema oscuro por defecto
        self.current_theme = 'darkly' # 'litera' (claro) o 'darkly' (oscuro)

        # Diccionario idiomas (solo textos usados en UI)
        self.texts = {
            'es': {
                'escaneos': "Escaneos",
                'hashes': "Hashes Maliciosos",
                'configuracion': "Configuración",
                'titulo': "Antivirus",
                'descripcion': "Protección básica del sistema",
                'escaneo_rapido': "Escaneo Rápido",
                'escaneo_completo': "Escaneo Completo",
                'refrescar': "Refrescar",
                'confirmar_escaneo': "Confirmar escaneo completo",
                'confirmar_escaneo_msg': "Esto puede tardar bastante. ¿Estás seguro?",
                'tema': "Tema",
                'idioma': "Idioma",
                'claro': "Claro",
                'oscuro': "Oscuro",
                'espanol': "Español",
                'ingles': "Inglés"
            },
            'en': {
                'escaneos': "Scans",
                'hashes': "Malicious Hashes",
                'configuracion': "Settings",
                'titulo': "Antivirus",
                'descripcion': "Basic system protection",
                'escaneo_rapido': "Quick Scan",
                'escaneo_completo': "Full Scan",
                'refrescar': "Refresh",
                'confirmar_escaneo': "Confirm full scan",
                'confirmar_escaneo_msg': "This might take a while. Are you sure?",
                'tema': "Theme",
                'idioma': "Language",
                'claro': "Light",
                'oscuro': "Dark",
                'espanol': "Spanish",
                'ingles': "English"
            }
        }

        self.current_lang = 'es'

        self.antivirus = Antivirus(mostrar_func=self.mostrar, gui=self)

        self.construir_interfaz()
        self.antivirus.comprobar_privilegios()

        self.root.protocol("WM_DELETE_WINDOW", self.cerrar)

    def construir_interfaz(self):
        # Panel lateral izquierdo
        self.sidebar = Frame(self.root, width=200, padding=10)
        self.sidebar.pack(side=LEFT, fill=Y)

        # Panel principal derecho
        self.main_panel = Frame(self.root, padding=10)
        self.main_panel.pack(side=RIGHT, fill=BOTH, expand=YES)

        # Botones en sidebar
        self.btn_escaneos = Button(self.sidebar, text=self.texts[self.current_lang]['escaneos'],
                                   bootstyle="info", width=20, command=self.mostrar_escaneos)
        self.btn_escaneos.pack(pady=5)

        self.btn_hashes = Button(self.sidebar, text=self.texts[self.current_lang]['hashes'],
                                 bootstyle="info", width=20, command=self.mostrar_hashes)
        self.btn_hashes.pack(pady=5)

        self.btn_config = Button(self.sidebar, text=self.texts[self.current_lang]['configuracion'],
                                 bootstyle="info", width=20, command=self.mostrar_config)
        self.btn_config.pack(pady=5)

        # Frames para cada sección
        self.frame_escaneos = Frame(self.main_panel)
        self.frame_hashes = Frame(self.main_panel)
        self.frame_config = Frame(self.main_panel)

        self.construir_tab_escaneos()
        self.construir_tab_hashes()
        self.construir_tab_config()

        # Mostrar pestaña escaneos al inicio
        self.mostrar_escaneos()

    def ocultar_frames(self):
        self.frame_escaneos.pack_forget()
        self.frame_hashes.pack_forget()
        self.frame_config.pack_forget()

    def construir_tab_escaneos(self):
        Label(self.frame_escaneos, text=self.texts[self.current_lang]['titulo'], font=("Segoe UI", 20, "bold")).pack(anchor=W)
        Label(self.frame_escaneos, text=self.texts[self.current_lang]['descripcion'], font=("Segoe UI", 12)).pack(anchor=W)

        botones = Frame(self.frame_escaneos, padding=(0, 10))
        botones.pack(fill=X)

        self.btn_rapido = Button(botones, text=self.texts[self.current_lang]['escaneo_rapido'],
                                 bootstyle="primary", width=20, command=self.hilo_escanear_rapido)
        self.btn_rapido.pack(side=LEFT, padx=10)

        self.btn_completo = Button(botones, text=self.texts[self.current_lang]['escaneo_completo'],
                                   bootstyle="warning", width=20, command=self.hilo_escanear_completo)
        self.btn_completo.pack(side=LEFT, padx=10)

        self.btn_detener = Button(botones, text="Detener escaneo", bootstyle="danger", width=20,
                                  command=self.detener_escaneo, state="disabled")
        self.btn_detener.pack(side=LEFT, padx=10)

        salida_frame = Frame(self.frame_escaneos)
        salida_frame.pack(fill=BOTH, expand=YES)

        self.text_area = ScrolledText(salida_frame, wrap="word", height=20)
        self.text_area.pack(fill=BOTH, expand=YES)

    def construir_tab_hashes(self):
        self.tree = Treeview(self.frame_hashes, columns=("Hash", "Fuente", "Fecha"), show='headings', height=15)
        self.tree.heading("Hash", text="Hash")
        self.tree.heading("Fuente", text="Fuente")
        self.tree.heading("Fecha", text="Fecha")
        self.tree.column("Hash", width=300)
        self.tree.column("Fuente", width=100)
        self.tree.column("Fecha", width=150)
        self.tree.pack(fill=BOTH, expand=YES)

        Button(self.frame_hashes, text=self.texts[self.current_lang]['refrescar'], bootstyle="secondary",
               command=self.actualizar_hashes).pack(pady=10)

        self.actualizar_hashes()

    def construir_tab_config(self):
        Label(self.frame_config, text=self.texts[self.current_lang]['configuracion'], font=("Segoe UI", 16, "bold")).pack(anchor=W, pady=(0, 10))

        # Tema
        Label(self.frame_config, text=self.texts[self.current_lang]['tema'], font=("Segoe UI", 12)).pack(anchor=W)
        self.btn_tema = Button(self.frame_config, text=self.texts[self.current_lang]['oscuro'], bootstyle="secondary",
                               width=15, command=self.cambiar_tema)
        self.btn_tema.pack(pady=(0, 15))

        # Idioma
        Label(self.frame_config, text=self.texts[self.current_lang]['idioma'], font=("Segoe UI", 12)).pack(anchor=W)
        self.btn_idioma = Button(self.frame_config, text=self.texts[self.current_lang]['ingles'], bootstyle="secondary",
                                 width=15, command=self.cambiar_idioma)
        self.btn_idioma.pack()

    def preparar_escaneo(self, tipo):
        self.antivirus.detener = False
        self.btn_detener.config(state="normal")

        if tipo == 'rapido':
            self.btn_rapido.config(state="normal")
            self.btn_completo.config(state="disabled") # Deshabilitamos el escaneo opuesto
        elif tipo == 'completo':
            self.btn_completo.config(state="normal")
            self.btn_rapido.config(state="disabled")
        else:
            # Por si acaso
            self.btn_rapido.config(state="normal")
            self.btn_completo.config(state="normal")

        self.text_area.delete(1.0, "end") # Limpiar área de salida

    def finalizar_escaneo(self):
        self.btn_rapido.config(state="normal")
        self.btn_completo.config(state="normal")
        self.btn_detener.config(state="normal")

    def _escanear_rapido(self):
        self.antivirus.escaneo_rapido()
        self.finalizar_escaneo()

    def _escanear_completo(self):
        self.antivirus.escaneo_completo()
        self.finalizar_escaneo()

    def detener_escaneo(self):
        self.antivirus.detener = True
        self.btn_rapido.config(state="normal")
        self.btn_completo.config(state="normal")
        self.btn_detener.config(state="disabled")
        messagebox.showinfo(self.texts[self.current_lang]['titulo'], "Escaneo detenido.")

    def mostrar_escaneos(self):
        self.ocultar_frames()
        self.frame_escaneos.pack(fill=BOTH, expand=YES)

    def mostrar_hashes(self):
        self.ocultar_frames()
        self.frame_hashes.pack(fill=BOTH, expand=YES)

    def mostrar_config(self):
        self.ocultar_frames()
        self.frame_config.pack(fill=BOTH, expand=YES)

    def actualizar_hashes(self):
        for fila in self.tree.get_children():
            self.tree.delete(fila)

        hashes = self.antivirus.hash_db.obtener_todos()
        for id_, hash_valor, fuente, fecha in hashes:
            self.tree.insert("", END, values=(hash_valor, fuente, fecha))

    def mostrar(self, texto):
        self.text_area.insert("end", texto + "\n")
        self.text_area.see("end")

    def hilo_escanear_rapido(self):
        self.preparar_escaneo('rapido')
        threading.Thread(target=self._escanear_rapido, daemon=True).start()

    def hilo_escanear_completo(self):
        respuesta = messagebox.askyesno(
            self.texts[self.current_lang]['confirmar_escaneo'],
            self.texts[self.current_lang]['confirmar_escaneo_msg'])
        if respuesta:
            self.preparar_escaneo('completo')
            threading.Thread(target=self._escanear_completo, daemon=True).start()

    def cambiar_tema(self):
        if self.current_theme == 'litera':
            self.current_theme = 'darkly'
            self.style.theme_use('darkly')
            self.btn_tema.config(text=self.texts[self.current_lang]['claro'])
        else:
            self.current_theme = 'litera'
            self.style.theme_use('litera')
            self.btn_tema.config(text=self.texts[self.current_lang]['oscuro'])

    def cambiar_idioma(self):
        if self.current_lang == 'es':
            self.current_lang = 'en'
            self.btn_idioma.config(text=self.texts['en']['espanol'])
        else:
            self.current_lang = 'es'
            self.btn_idioma.config(text=self.texts['es']['ingles'])
        self.actualizar_textos()

    def actualizar_textos(self):
        # Actualizar textos de botones laterales
        self.btn_escaneos.config(text=self.texts[self.current_lang]['escaneos'])
        self.btn_hashes.config(text=self.texts[self.current_lang]['hashes'])
        self.btn_config.config(text=self.texts[self.current_lang]['configuracion'])

        # Actualizar textos de tabs (reconstruir contenido)
        # Mejor reconstruir por simplicidad
        for widget in self.frame_escaneos.winfo_children():
            widget.destroy()
        self.construir_tab_escaneos()

        for widget in self.frame_hashes.winfo_children():
            widget.destroy()
        self.construir_tab_hashes()

        for widget in self.frame_config.winfo_children():
            widget.destroy()
        self.construir_tab_config()

        # Mostrar la pestaña activa para que se refresque el contenido
        # Aquí asumimos que el frame visible es el que debe refrescar
        if self.frame_escaneos.winfo_ismapped():
            self.mostrar_escaneos()
        elif self.frame_hashes.winfo_ismapped():
            self.mostrar_hashes()
        elif self.frame_config.winfo_ismapped():
            self.mostrar_config()

    def ventana_opciones_amenaza(self, archivo, amenaza):
        ventana = Toplevel(self.root)
        ventana.title("Alerta de Antivirus")
        ventana.geometry("460x180")
        ventana.resizable(False, False)
        ventana.grab_set()  # Modal: evita interacción con ventana principal

        from ttkbootstrap import Label as TbLabel, Button as TbButton
        label = TbLabel(ventana, text=f"Se ha detectado una amenaza por {amenaza}.\n¿Qué deseas hacer con:\n{archivo}?",
                        wraplength=440, justify="left")
        label.pack(padx=10, pady=15)

        resultado = {"opcion": None}

        def opcion1():
            resultado["opcion"] = "1"
            ventana.destroy()

        def opcion2():
            resultado["opcion"] = "2"
            ventana.destroy()

        def opcion3():
            resultado["opcion"] = "3"
            ventana.destroy()

        frame_botones = Frame(ventana)
        frame_botones.pack(pady=10)

        btn1 = TbButton(frame_botones, text="🛑 Mover a cuarentena", width=18, command=opcion1)
        btn1.grid(row=0, column=0, padx=5)

        btn2 = TbButton(frame_botones, text="❌ Eliminar archivo", width=18, command=opcion2)
        btn2.grid(row=0, column=1, padx=5)

        btn3 = TbButton(frame_botones, text="✅ Ignorar archivo", width=18, command=opcion3)
        btn3.grid(row=0, column=2, padx=5)

        ventana.wait_window()
        return resultado["opcion"]

    def mostrar_opciones_amenaza(self, archivo, accion_requerida):
        opcion = self.ventana_opciones_amenaza(archivo, accion_requerida)

        if opcion == "1":
            self.antivirus.quarantine.mover_a_cuarentena(archivo)
            self.antivirus.quarantine.proteger_directorio(self.antivirus.quarantine.carpeta)
            self.antivirus.logger.registrar_log(archivo, accion_requerida, "cuarentena")
            self.mostrar(f"🛑 Archivo movido a cuarentena: {archivo}")

        elif opcion == "2":
            import os
            try:
                os.remove(archivo)
                self.mostrar(f"❌ Archivo eliminado: {archivo}")
                self.antivirus.logger.registrar_log(archivo, accion_requerida, "eliminado")
            except Exception as e:
                self.mostrar(f"Error al eliminar archivo: {e}")

        elif opcion == "3":
            hash_archivo = self.antivirus.hash_analyzer.calcular_hash(archivo)
            self.antivirus.virus_ignorados.add(hash_archivo)
            self.antivirus.guardar_ignorados()
            self.mostrar(f"🟢 El archivo ha sido ignorado. No se volverá a marcar como amenaza.")
            self.antivirus.logger.registrar_log(archivo, accion_requerida, "ignorado")

        else:
            self.mostrar("⚠️ Opción no válida. No se realizó ninguna acción.")

    def cerrar(self):
        if not self.antivirus.detener:
            self.antivirus.limpiar_estado_escaneo()
        self.root.destroy()

