import tkinter as tk
from tkinter import Toplevel, Frame
from ttkbootstrap import Label as TbLabel, Button as TbButton

def ventana_opciones_amenaza(root, archivo, amenaza):
    ventana = Toplevel(root)
    ventana.title("Alerta de Antivirus")
    ventana.geometry("460x180")
    ventana.resizable(False, False)
    ventana.grab_set()

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

root = tk.Tk()
root.withdraw()  # Oculto ventana principal para pruebas

opcion = ventana_opciones_amenaza(root, "archivo_ejemplo.exe", "heurística")
print("Opción elegida:", opcion)
root.mainloop()
