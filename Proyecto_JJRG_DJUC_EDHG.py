from tkinter import *
from tkinter import messagebox, filedialog, ttk 
import json
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64
import pyperclip
from datetime import datetime
import time
from datetime import datetime
import tkinter.font as tkFont
from tkinter import Toplevel, Label, Button, Entry, Frame, ttk
from tkcalendar import Calendar
from PIL import Image, ImageTk 
import os
class Extras: 
    def __init__(self,extra1,extra2,extra3,extra4,extra5):
        self.extra1 = extra1
        self.extra2 = extra2
        self.extra3 = extra3
        self.extra4 = extra4
        self.extra5 = extra5
    
    def to_dict(self):
      return {
        "extra1": self.extra1,
        "extra2": self.extra2,
        "extra3": self.extra3,
        "extra4": self.extra4,
        "extra5": self.extra5
      }
class Pagina:
    
    def __init__(self,id,site_name,username,password,url,notes,extra_fields: Extras):
        self.id = id
        self.site_name = site_name    
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.extra_fields = extra_fields     
class Entrada:
    def __init__(self,pagina:Pagina,tags,creation_date,update_date,expiration_date,icon):
        self.pagina = pagina
        self.tags = tags
        self.creation_date = creation_date
        self.update_date = update_date
        self.expiration_date = expiration_date
        self.icon = icon      
    def to_dict(self):
        return {
            "id": self.pagina.id,
            "site_name": self.pagina.site_name,
            "username": self.pagina.username,
            "password": self.pagina.password,
            "url": self.pagina.url,
            "notes": self.pagina.notes,
            "extra_fields": self.pagina.extra_fields.to_dict(),
            "tags": self.tags,
            "creation_date": self.creation_date,
            "update_date": self.update_date,
            "expiration_date": self.expiration_date,
            "icon": self.icon
        }
#Variables globales
encrypteddata = ""
decrypteddata = ""
alldata = {}
lista = {}
masterkey = "12345678"
locktime = 30
copytime = 30
# Claves RSA
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjI4EwndbkBcAXGopGUUY
0w3VAUcNK3GuOzFKf/7wpmAgQq9Ld7n9I6eSRMwO1299qNWh1e8xmH+VXN6EG0dt
I+NCh/MS6b0/peQzI0hW136MS0s0F8k7mFXHPuDy81a3Vz8BBU8+V3crx1rP48l0
NU/xguq67SkuJvDWSrs5f4ydgYHcK0hD6yO8tWA8EyB+JRMEugmz/RUOLkvoNBTU
CG8k0lgXFE3CeTNQaJG5Dbyn5Mw8+NT4avRM1JATUZyjSQKAt9QD/dyQufe5hWL7
xxOh2N15v0k3TrBM3JQefVqfW2ajlDWzrv0kQv7kxRgXECdaquXmDMQGKnnRJS62
HQIDAQAB
-----END PUBLIC KEY-----"""
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjI4EwndbkBcAXGopGUUY0w3VAUcNK3GuOzFKf/7wpmAgQq9L
d7n9I6eSRMwO1299qNWh1e8xmH+VXN6EG0dtI+NCh/MS6b0/peQzI0hW136MS0s0
F8k7mFXHPuDy81a3Vz8BBU8+V3crx1rP48l0NU/xguq67SkuJvDWSrs5f4ydgYHc
K0hD6yO8tWA8EyB+JRMEugmz/RUOLkvoNBTUCG8k0lgXFE3CeTNQaJG5Dbyn5Mw8
+NT4avRM1JATUZyjSQKAt9QD/dyQufe5hWL7xxOh2N15v0k3TrBM3JQefVqfW2aj
lDWzrv0kQv7kxRgXECdaquXmDMQGKnnRJS62HQIDAQABAoIBABn/Ys39ecgrGPv+
/t8XssHG+zEjTUJN4qY8NcV7CFQdz5nGBrV8h2AC7MEg5VXf32RNL4P8nDXS03O8
DL9m9L8AmBvBUCw/vvgWP4c1KCrv009R9662n/lLVHFC9m0gCwVuN+gdgjB3cHeN
Soqdhosd4FQQysZ3KXw2a8yi2L3IpDqTwSBLCCKcwylTXAJwT02L9JhmJRi26y7N
WIX14TUfvj6cYfaCGuQH37JZ293yaJ9uSkQvKQ3rN+H6o8T57rh1N+1B8R8zvySk
QiKrNZ94atCrnsvawEkQIIWqX3kmTd0nawbTG7/vgSFoXWdGx7jM7TLGK/3JCh97
3cygQJkCgYEAyzzB6KinVUgACZF5SqIVNBkFDFvOTyysKFKHEy0UtM3VWIPN23BY
DqCo0/Zt/Nf3Xkojzo9fKsQ1XXKdrA4thXr4pWduBKe9lv2IPl0aFZrgiGx87Au9
O1+ReICnIgy2k17sUEJRegG0ZXigq1uoSkN7v1wm6nQiQHnYLy5vIxMCgYEAsQtZ
iDoE+7Iy/pL5oEQN/3WJYmsZRtmIXecTya4f8bfbPKaBxf2rlr3Us+YMSfZd4PGQ
G+mev09kuHLqTJPcLe5kvj6pW5nESOw37DT4QxSLv9Cuc0Wc4EXIVh3GnFFuozUB
plprqwUG1SgwCrR9Cpn40P9acSS2DEyywP9yuA8CgYBQB8HX6ynRdEPHgMiBcifl
VwDc5/3qwY2dZzoXfAYOWIttiqFyit+yCuPQa9bN3QFk2M8W1PBFt/PHs42RJhgY
2t60y3DQVnlazsVqwWC3J0DJl+btUIYYrj5rdEXcK6NtjtCBnkvVPnyaBJFISRSR
Adfl99S/ODIQr6pIkgFjjwKBgQCb2f3q6ghQ+cHiUMfmyYH5DCLwvI73y6872puU
wu/j/ZHFhl5fSLuwa1O/Ohg/U924k23k5HeWufFUXfTbjJ4a4O1WfBriRC6Cc0+X
Y9nYU1HifXXUi8dZtpRxGq0oFpdqnNLi+l4lorstEb+Y7OHWX0ylzuRzDXokwa/q
LfVzCQKBgDuUG9QSyqoq14rj2ntsXMnazDekMotxjJkDB/xbF+9i4FuiOS7uGXK2
Aq9Eh1aLBvtSgpKmZBzf4ELH9RcLGC7pc2Tg0WgpRG4fm4Eyyc5dkU7hMFBRLMhO
WjAvT7mtB7wwRLfPlx1aaWFQJQaoBWAzVFfu+uJZ38CJ9V1OEmc5
-----END RSA PRIVATE KEY-----"""
# Funciones para encriptar y desencriptar contraseñas individuales con RSA
def encrypt_password(password):
    try:
        rsa_key = RSA.import_key(PUBLIC_KEY)
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        encrypted_password = cipher_rsa.encrypt(password.encode('utf-8'))
        return base64.b64encode(encrypted_password).decode('utf-8')
    except Exception as e:
        print(f"Error en la encriptación de la contraseña: {e}")
        raise
def decrypt_password(encrypted_password):
    try:
        rsa_key = RSA.import_key(PRIVATE_KEY)
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        decoded_password = base64.b64decode(encrypted_password)
        sentinel = b"ERROR"
        decrypted_password = cipher_rsa.decrypt(decoded_password, sentinel)
        if decrypted_password == sentinel:
            raise ValueError("La desencriptación falló debido a padding incorrecto o clave incorrecta.")
        return decrypted_password.decode('utf-8')
    except Exception as e:
        print(f"Error en la desencriptación de la contraseña: {e}")
        raise
# Funciones de padding para DES
def pad(data):
    padding_len = 8 - (len(data) % 8)
    padding = bytes([padding_len]) * padding_len
    return data + padding
def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]
def decrypt_json(path, DESkey):
    global alldata
    key = DESkey.encode("utf-8")
    with open(path, "rb") as file:
        encrypteddata = file.read()
    cipher = DES.new(key, DES.MODE_ECB)
    decrypteddata = cipher.decrypt(encrypteddata)
    decrypteddata = unpad(decrypteddata)
    jsondata = json.loads(decrypteddata.decode("utf-8"))

    for entry in jsondata["entries"]:
        entry["password"] = decrypt_password(entry["password"])
        
    for entry in jsondata["entries"]:
        extra_fields_data = entry["extra_fields"]
        extra_fields = Extras(
            extra_fields_data["extra1"],
            extra_fields_data["extra2"],
            extra_fields_data["extra3"],
            extra_fields_data["extra4"],
            extra_fields_data["extra5"]
        )
        
        pagina = Pagina(
            entry["id"],
            entry["site_name"],
            entry["username"],  
            entry["password"],
            entry["url"],
            entry["notes"],
            extra_fields
        )
        
        entry_obj = Entrada(
            pagina,
            entry["tags"],
            entry["creation_date"],
            entry["update_date"],
            entry["expiration_date"],
            entry["icon"]
        )
        
        alldata[entry["id"]] = entry_obj
# Función para encriptar y guardar el archivo JSON
def encrypt_json(path, DESkey):
    global alldata, masterkey
    data_to_encrypt = {"entries": []}
    for entry_id, entry in alldata.items():
        entry_dict = entry.to_dict()
        entry_dict["password"] = encrypt_password(entry.pagina.password)
        data_to_encrypt["entries"].append(entry_dict)
    plain_json_path = path.replace(".enc", ".json")  
    with open(plain_json_path, "w", encoding="utf-8") as file:
        json.dump(data_to_encrypt, file, indent=4, ensure_ascii=False)     
    with open(plain_json_path, "r", encoding="utf-8") as file:
        json_data = file.read().encode("utf-8")  # Leer y convertir a bytes
    padded_data = custom_pad(json_data, DES.block_size)
    key = DESkey.encode("utf-8")
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    with open(path, "wb") as file:
        file.write(encrypted_data)
    messagebox.showinfo("Éxito", "Archivo encriptado y guardado correctamente.")
# Función para encriptar y guardar el archivo JSON
def encrypt_json2(path, DESkey, option):
    global lista, masterkey
    data_to_encrypt = {"entries": []}
    for entry_id, entry in lista.items():
        entry_dict = entry.to_dict()
        entry_dict["password"] = encrypt_password(entry.pagina.password)
        data_to_encrypt["entries"].append(entry_dict)
    plain_json_path = path.replace(".enc", ".json")  
    with open(plain_json_path, "w", encoding="utf-8") as file:
        json.dump(data_to_encrypt, file, indent=4, ensure_ascii=False)     
    with open(plain_json_path, "r", encoding="utf-8") as file:
        json_data = file.read().encode("utf-8")  
    padded_data = custom_pad(json_data, DES.block_size)
    key = DESkey.encode("utf-8")
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    with open(path, "wb") as file:
        file.write(encrypted_data)
    messagebox.showinfo("Éxito", "Archivo encriptado y guardado correctamente.")     
# Función de padding manual para PKCS#7
def custom_pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def select_icon():
    icon_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif")])
    if icon_path:
        entry_icon.delete(0, END)  
        entry_icon.insert(0, icon_path)

def add_entry():
    global alldata
    entry_id = len(alldata)
    extra_fields = Extras(
        entry_extra1.get(),
        entry_extra2.get(),
        entry_extra3.get(),
        entry_extra4.get(),
        entry_extra5.get()
    )
    pagina = Pagina(
        id=entry_id,
        site_name=entry_site.get(),
        username=entry_username.get(),
        password=entry_password.get(),
        url=entry_url.get(),
        notes=entry_notes.get(),
        extra_fields=extra_fields
    )

    entry_obj = Entrada(
        pagina=pagina,
        tags=entry_tags.get().split(","),
        creation_date=datetime.now().isoformat(),
        update_date=datetime.now().isoformat(),
        expiration_date=entry_expiration_date.get(),
        icon=entry_icon.get()
    )
    alldata[entry_id] = entry_obj
    messagebox.showinfo("Éxito", "Entrada añadida correctamente.")
def open_encryption_window():
    global masterkey, alldata
    def load_encrypted_file():
        global masterkey, alldata
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if path:
            if masterkey:
                try:
                    alldata.clear()
                    decrypt_json(path, masterkey)
                    messagebox.showinfo("Éxito", "Archivo desencriptado y cargado correctamente.")
                except Exception as e:
                    messagebox.showerror("Error", f"Fallo al desencriptar: {e}")
            else:
                messagebox.showwarning("Llave DES requerida", "Por favor ingresa una llave DES.")

    def save_encrypted_file():
        global masterkey, alldata
        path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if path:
            if masterkey:
                try:
                    encrypt_json(path, masterkey)
                    messagebox.showinfo("Éxito", "Archivo encriptado y guardado correctamente.")
                except Exception as e:
                    messagebox.showerror("Error", f"Fallo al encriptar: {e}")
            else:
                messagebox.showwarning("Llave DES requerida", "Por favor ingresa una llave DES.")

    encryption_window = Toplevel(mainwindow)
    encryption_window.title("Encriptar/Desencriptar Archivo")
    encryption_window.geometry("400x150")
    encryption_window.configure(bg="#D3D3D3") 
    Button(encryption_window, text="Cargar y desencriptar archivo", command=load_encrypted_file).pack(pady=10)
    Button(encryption_window, text="Guardar archivo encriptado", command=save_encrypted_file).pack(pady=10)
    Button(encryption_window, text="Exportar a Texto Plano", command=export_to_plain_text).pack(pady=10)
    
def export_to_plain_text():
    data_to_export = {"entries": [entry.to_dict() for entry in alldata.values()]}
    with open("exported_data.json", "w", encoding="utf-8") as file:
        json.dump(data_to_export, file, indent=4, ensure_ascii=False)

    messagebox.showinfo("Exportación Exitosa", "Los datos han sido exportados a 'exported_data.json' en formato JSON.")
def initial_window():
    global masterkey
    def open_encrypted_file():
        global masterkey
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            masterkey = entry_key.get()
            if masterkey:
                try:
                    alldata.clear()
                    decrypt_json(file_path, masterkey) 
                    messagebox.showinfo("Éxito", "Archivo encriptado cargado correctamente.")
                    mainwindow.deiconify()
                    window1.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Fallo al desencriptar: {e}")

    def open_plain_file():
        global masterkey, alldata
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            masterkey = entry_key.get()
        if len(masterkey) == 8:
            try:
                with open(file_path, "r") as file:
                    jsondata = json.load(file)
                alldata.clear() 
                for entry in jsondata["entries"]:
                    extra_fields_data = entry["extra_fields"]
                    extra_fields = Extras(
                        extra_fields_data["extra1"],
                        extra_fields_data["extra2"],
                        extra_fields_data["extra3"],
                        extra_fields_data["extra4"],
                        extra_fields_data["extra5"]
                    )
                    
                    pagina = Pagina(
                        entry["id"],
                        entry["site_name"],
                        entry["username"],
                        entry["password"],  
                        entry["url"],
                        entry["notes"],
                        extra_fields
                    )
                    
                    entry_obj = Entrada(
                        pagina,
                        entry["tags"],
                        entry["creation_date"],
                        entry["update_date"],
                        entry["expiration_date"],
                        entry["icon"]
                    )
                    
                    alldata[entry["id"]] = entry_obj 
                
                messagebox.showinfo("Éxito", "Archivo de texto plano cargado correctamente.")
                mainwindow.deiconify()
                window1.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Fallo al cargar archivo de texto plano: {e}")
        else:
            messagebox.showerror("Error", "La clave DES debe tener exactamente 8 bytes.")
            

    def new_file():
        global masterkey
        masterkey = entry_key.get()
        if len(masterkey) == 8:
            alldata.clear()  
            mainwindow.deiconify()
            window1.destroy()
        else:
            messagebox.showerror("Error", "La clave DES debe tener exactamente 8 bytes.")

    window1 = Tk()
    window1.geometry("400x300")
    window1.title("Bienvenido")
    window1.configure(bg="#D3D3D3")
    Label(window1, text="¿Deseas abrir un archivo existente o crear uno nuevo?").pack(pady=10)
    Label(window1, text="Clave DES (solo para archivos encriptados):").pack(pady=5)
    entry_key = Entry(window1, show="*", width=50)
    entry_key.pack(pady=5)
    Button(window1, text="Abrir archivo encriptado", command=open_encrypted_file).pack(pady=10)
    Button(window1, text="Abrir archivo de texto plano", command=open_plain_file).pack(pady=10)

    Button(window1, text="Crear nuevo archivo", command=new_file).pack(pady=10)

    window1.mainloop()

def DataDisplay():
    global alldata, lista
    def add_to_list():
        selected_item = data.selection()
        if selected_item:
            values = data.item(selected_item)["values"]
            lista[values[0]] = alldata[values[0]]
            print()
    def copy_selection():
        global copytime
        selected_item = data.selection()
        if selected_item:
            item_values = data.item(selected_item)["values"]
            DataWindow.clipboard_clear()
            copied_text = item_values[4]
            pyperclip.copy(copied_text)
            messagebox.showinfo("Copiado", f"Copiado al portapapeles:\n{copied_text}")
            DataWindow.after(copytime*1000,clearcontent)
        else:
            messagebox.showwarning("Advertencia", "No hay selección para copiar.")
    def clearcontent():
        pyperclip.copy("")
        messagebox.showinfo("Expirado", f"Pasaron {copytime} segundos, portapapeles limpio")
    def on_select(event):
        if data.selection():
            copy_button.config(state="normal")
        else:
            copy_button.config(state="disabled")
    def edit_selection():
        selected_item = data.selection()
        if selected_item:
            item_values = data.item(selected_item)["values"]
            registroaeditar = alldata[item_values[0]]
            EditData(registroaeditar)            
        else:
            messagebox.showwarning("Advertencia", "No hay selección para editar.")
                    
    DataWindow = Toplevel(mainwindow)
    DataWindow.title("My Data")
    DataWindow.geometry("600x600")
    mainwindow.configure(bg="#D3D3D3") 
    
    columns = ("ID", "Nombre de usuario", "Sitio", "URL", "Contraseña","Icon")
    data = ttk.Treeview(DataWindow, columns=columns, show="headings")
    data.heading("ID", text="ID")
    data.heading("Nombre de usuario", text="Nombre de usuario")
    data.heading("Sitio", text="Sitio")
    data.heading("URL", text="URL")
    data.heading("Contraseña", text="Contraseña")
    data.heading("Icon", text="Icon")

    for entry_id, entry in alldata.items():
        if entry == []:  
            continue
        icon_path = entry.icon
        if os.path.exists(icon_path):
            image = Image.open(icon_path)
            image = image.resize((10,10,),Image.LANCZOS)
            iconimage = ImageTk.PhotoImage(image)
            data.insert("", "end", values=(
                entry.pagina.id,
                entry.pagina.username,
                entry.pagina.site_name,
                entry.pagina.url,
                entry.pagina.password),
                image=iconimage
            )
            data.imageref = iconimage
        else:
            data.insert("", "end", values=(
                entry.pagina.id,
                entry.pagina.username,
                entry.pagina.site_name,
                entry.pagina.url,
                entry.pagina.password,
                entry.icon
            ))
            
        
    def view_list():
        ListWindow = Toplevel(DataWindow)
        ListWindow.title("Lista de Seleccionados")
        ListWindow.geometry("600x400")

        Listaver = ttk.Treeview(ListWindow, columns=("ID", "Usuario", "Sitio", "URL", "Contraseña"), show="headings")
        Listaver.heading("ID", text="ID")
        Listaver.heading("Usuario", text="Usuario")
        Listaver.heading("Sitio", text="Sitio")
        Listaver.heading("URL", text="URL")
        Listaver.heading("Contraseña", text="Contraseña")
        Listaver.pack(fill="both", expand=True, pady=10)
        
        for entry_id, entry in lista.items():
            if entry == []:  
                continue
            Listaver.insert("", "end", values=(
                entry.pagina.id,
                entry.pagina.username,
                entry.pagina.site_name,
                entry.pagina.url,
                entry.pagina.password
            ))
    def export():
        path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if path:
            if masterkey:
                try:
                    encrypt_json2(path, masterkey,1)
                    messagebox.showinfo("Éxito", "Archivo de listas encriptado y guardado correctamente.")
                except Exception as e:
                    messagebox.showerror("Error", f"Fallo al encriptar: {e}")
            else:
                messagebox.showwarning("Llave DES requerida", "Por favor ingresa una llave DES.")        

    
    data.pack(fill="both", expand=True)
    data.bind("<<TreeviewSelect>>", on_select)
    copy_button = Button(DataWindow, text="Copiar selección", command=copy_selection, state="disabled")
    copy_button.pack(pady=10)
    edit_button = Button(DataWindow, text="Editar registro",command=edit_selection)
    edit_button.pack(pady=20)
    Button(DataWindow, text="Agregar a la lista", command=add_to_list).pack(side="left", padx=10, pady=10)
    Button(DataWindow, text="Exportar lista", command=export).pack(side="left", padx=10, pady=10)
    Button(DataWindow, text="Ver lista", command=view_list).pack(side="left", padx=10, pady=10)
def EditData(entrada: Entrada):
    global alldata
    def show(event):
        item_id = data.identify_row(event.y)
        column_id = data.identify_column(event.x)
        
        if item_id and column_id:
            text = data.item(item_id, "values")[int(column_id[1:]) - 1]  
            tooltip.config(text=text)
            tooltip.place(x=event.x_root, y=event.y_root)
    def hide(event):
        tooltip.place_forget()
    def editar(option,text,id,temporal: Entrada):
        if option == 1:
            temporal.pagina.site_name = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[1] = text
            data.item("I002", values=values)
        elif option ==2:
            temporal.pagina.username = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[2] = text
            data.item("I002", values=values)
        elif option ==3: 
            temporal.pagina.password = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[3] = text
            data.item("I002", values=values)
        elif option ==4:
            temporal.pagina.url = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[4] = text
            data.item("I002", values=values)
        elif option ==5:
            temporal.pagina.notes = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[5] = text
            data.item("I002", values=values)
        elif option ==6:
            temporal.pagina.extra_fields.extra1 = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[6] = text
            data.item("I002", values=values)
        elif option ==7:
            temporal.pagina.extra_fields.extra2 = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[7] = text
            data.item("I002", values=values)
        elif option ==8:
            temporal.pagina.extra_fields.extra3 = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[8] = text
            data.item("I002", values=values)
        elif option ==9:
            temporal.pagina.extra_fields.extra4 = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[9] = text
            data.item("I002", values=values)
        elif option ==10:
            temporal.pagina.extra_fields.extra5 = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[10] = text
            data.item("I002", values=values)
        elif option ==11:
            temporal.tags = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[11] = text
            data.item("I002", values=values)
        elif option ==13:
            temporal.expiration_date = text
            temporal.update_date = datetime.now().isoformat()
            values = list(data.item("I002", "values"))
            values[13] = text
            data.item("I002", values=values)
    def confirm(temporal):
        alldata[entrada.pagina.id] = temporal
        
    EditWindow = Toplevel(mainwindow)
    EditWindow.title("Edit Data")
    EditWindow.geometry("600x600")
    EditWindow.configure(bg="#D3D3D3") 
    
    
    def select_new_expiration_date():
        calendar_window = Toplevel(EditWindow)
        calendar_window.title("Seleccionar Nueva Fecha de Expiración")
        calendar = Calendar(calendar_window, selectmode='day', date_pattern="yyyy-mm-dd")
        calendar.pack(pady=10)

        def save_date():
            date = calendar.get_date()
            dateobj = datetime.strptime(date, "%Y-%m-%d")
            full_date = datetime.combine(dateobj.date(), datetime.now().time()).astimezone()
            formatted_date = full_date.isoformat()
            entry_nED.delete(0, "end")
            entry_nED.insert(0, formatted_date)
            calendar_window.destroy()
    
        Button(calendar_window, text="Guardar Fecha", command=save_date).pack(pady=10)
    
    
    

    columns = ("ID", "Sitio", "User", "Password", "URL","notes","extra1","extra2","extra3","extra4","extra5","tags","icono","Expiracion")
    data = ttk.Treeview(EditWindow, columns=columns, show="headings")
    data.heading("ID", text="ID")
    data.heading("Sitio", text="Sitio")
    data.heading("User", text="User")
    data.heading("Password", text="Pssword")
    data.heading("URL", text="URL")
    data.heading("notes", text="notes")
    data.heading("extra1", text="extra1")
    data.heading("extra2", text="extra2")
    data.heading("extra3", text="extra3")
    data.heading("extra4", text="extra4")
    data.heading("extra5", text="extra5")
    data.heading("tags", text="tags")
    data.heading("icono", text="icono")
    data.heading("Expiracion", text="Expiracion")
    data.insert("", "end", values=(
            entrada.pagina.id,
            entrada.pagina.site_name,
            entrada.pagina.username,
            entrada.pagina.password,
            entrada.pagina.url,
            entrada.pagina.notes,
            entrada.pagina.extra_fields.extra1,
            entrada.pagina.extra_fields.extra2,
            entrada.pagina.extra_fields.extra3,
            entrada.pagina.extra_fields.extra4,
            entrada.pagina.extra_fields.extra5,
            ", ".join(entrada.tags),
            entrada.icon,
            entrada.expiration_date
        ))
    data.insert("", "end", values=(
            entrada.pagina.id,
            entrada.pagina.site_name,
            entrada.pagina.username,
            entrada.pagina.password,
            entrada.pagina.url,
            entrada.pagina.notes,
            entrada.pagina.extra_fields.extra1,
            entrada.pagina.extra_fields.extra2,
            entrada.pagina.extra_fields.extra3,
            entrada.pagina.extra_fields.extra4,
            entrada.pagina.extra_fields.extra5,
            ", ".join(entrada.tags),
            entrada.icon,
            entrada.expiration_date
        ))
    temporal = entrada
    data.pack()
    hsb = ttk.Scrollbar(EditWindow, orient="horizontal", command=data.xview)
    data.config(xscrollcommand=hsb.set)
    hsb.pack(fill="x")
    Label(EditWindow,text="New site name").place(x = 10, y = 250)
    entry_nsn = Entry(EditWindow)
    entry_nsn.place(x = 100, y = 250)
    Button(EditWindow, text= "Editar",command=lambda:editar(1,entry_nsn.get(),entrada.pagina.id,temporal)).place(x = 250, y = 250)
    Label(EditWindow,text="New user").place(x = 10, y = 350)
    entry_nu = Entry(EditWindow)
    entry_nu.place(x = 100, y = 350)
    Button(EditWindow, text= "Editar",command=lambda:editar(2,entry_nu.get(),entrada.pagina.id,temporal)).place(x = 250, y = 350)
    Label(EditWindow,text="New password").place(x = 10, y = 450)
    entry_np = Entry(EditWindow)
    entry_np.place(x = 100, y = 450)
    Button(EditWindow, text= "Editar",command=lambda:editar(3,entry_np.get(),entrada.pagina.id,temporal)).place(x = 250, y = 450)
    Label(EditWindow,text="New url").place(x = 10, y = 550)
    entry_nurl = Entry(EditWindow)
    entry_nurl.place(x = 100, y = 550)
    Button(EditWindow, text= "Editar",command=lambda:editar(4,entry_nurl.get(),entrada.pagina.id,temporal)).place(x = 250, y = 550)
    Label(EditWindow,text="New notes").place(x = 400, y = 250)
    entry_nno = Entry(EditWindow)
    entry_nno.place(x = 490, y = 250)
    Button(EditWindow, text= "Editar",command=lambda:editar(5,entry_nno.get(),entrada.pagina.id,temporal)).place(x = 640, y = 250)
    Label(EditWindow,text="New Extra1").place(x = 400, y = 350)
    entry_ne1 = Entry(EditWindow)
    entry_ne1.place(x = 490, y = 350)
    Button(EditWindow, text= "Editar",command=lambda:editar(6,entry_ne1.get(),entrada.pagina.id,temporal)).place(x = 640, y = 350)
    Label(EditWindow,text="New Extra2").place(x = 400, y = 450)
    entry_ne2 = Entry(EditWindow)
    entry_ne2.place(x = 490, y = 450)
    Button(EditWindow, text= "Editar",command=lambda:editar(7,entry_ne2.get(),entrada.pagina.id,temporal)).place(x = 640, y = 450)
    Label(EditWindow,text="New Extra3").place(x = 400, y = 550)
    entry_ne3 = Entry(EditWindow)
    entry_ne3.place(x = 490, y = 550)
    Button(EditWindow, text= "Editar",command=lambda:editar(8,entry_ne3.get(),entrada.pagina.id,temporal)).place(x = 640, y = 550)
    Label(EditWindow,text="New Extra4").place(x = 790, y = 250)
    entry_ne4 = Entry(EditWindow)
    entry_ne4.place(x = 880, y = 250)
    Button(EditWindow, text= "Editar",command=lambda:editar(9,entry_ne4.get(),entrada.pagina.id,temporal)).place(x = 1030, y = 250)
    Label(EditWindow,text="New Extra5").place(x = 790, y = 350)
    entry_ne5 = Entry(EditWindow)
    entry_ne5.place(x = 880, y = 350)
    Button(EditWindow, text= "Editar",command=lambda:editar(10,entry_ne5.get(),entrada.pagina.id,temporal)).place(x = 1030, y = 350)
    Label(EditWindow,text="New tags").place(x = 790, y = 450)
    entry_nt = Entry(EditWindow)
    entry_nt.place(x = 880, y = 450)
    Button(EditWindow, text= "Editar",command=lambda:editar(11,entry_nt.get(),entrada.pagina.id,temporal)).place(x = 1030, y = 450)
    Label(EditWindow,text="New Icon").place(x = 1150, y = 350)
    entry_nI = Entry(EditWindow)
    entry_nI.place(x = 880, y = 550)
    Button(EditWindow, text="Editar", command=lambda: editar(12, entry_nI.get(), entrada.pagina.id, temporal)).place(x=1130, y=450)
    Label(EditWindow, text="Nueva Fecha de\nExpiración").place(x=790, y=550)
    entry_nED = Entry(EditWindow, width=15)
    entry_nED.place(x=880, y=550)
    Button(EditWindow, text="Seleccionar Fecha", command=select_new_expiration_date).place(x=1040, y=545)
    Button(EditWindow, text= "Editar",command=lambda:editar(13,entry_nED.get(),entrada.pagina.id,temporal)).place(x = 1040, y = 580)
    data.bind("<Motion>", show)
    data.bind("<Leave>", hide)
    tooltip = Label(EditWindow, bg="yellow", text="", wraplength=200)
    Button(EditWindow,text= "Confirmar cambios",command=lambda:confirm(temporal)).place(x = 550, y = 600 )
def open_options_window():
    global masterkey, locktime, copytime
    def change_master_key():
        global masterkey
        new_key = entry_new_key.get()
        if len(new_key) != 8:
            messagebox.showerror("Error", "La nueva clave DES debe tener exactamente 8 caracteres.")
            return
        masterkey = new_key
        messagebox.showinfo("Éxito", "Clave maestra cambiada correctamente.")

    def setlocktime():
        global locktime
        try:
            locktime = int(entry_lock_time.get())
            if locktime <= 0:
                raise ValueError
            locktime = locktime
            messagebox.showinfo("Éxito", f"Tiempo de bloqueo establecido en {locktime} segundos.")
        except ValueError:
            messagebox.showerror("Error", "Por favor ingresa un número válido mayor a 0.")

    options_window = Toplevel(mainwindow)
    options_window.title("Opciones")
    options_window.geometry("400x450")
    options_window.configure(bg="#D3D3D3") 

    Label(options_window, text="Nueva Clave DES (8 caracteres):").pack(pady=10)
    entry_new_key = Entry(options_window, show="*")
    entry_new_key.pack(pady=5)
    Button(options_window, text="Cambiar Clave Maestra", command=change_master_key).pack(pady=10)

    Label(options_window, text="Tiempo de bloqueo (en segundos):").pack(pady=10)
    entry_lock_time = Entry(options_window)
    entry_lock_time.pack(pady=5)
    Button(options_window, text="Establecer Tiempo de Bloqueo", command=setlocktime).pack(pady=10)
    
    Label(options_window, text="Tiempo de borrado del portapapeles (en segundos):").pack(pady=10)
    clipboard_clear_time_entry = Entry(options_window)
    clipboard_clear_time_entry.pack(pady=5)
    
    def setcopytime():
        global copytime
        try:
            copytime = int(clipboard_clear_time_entry.get())
            if copytime < 0:
                raise ValueError
            messagebox.showinfo("Éxito", f"Tiempo de borrado del portapapeles establecido en {copytime} segundos.")
        except ValueError:
            messagebox.showerror("Error", "Por favor, ingrese un número válido para el tiempo de borrado del portapapeles.")

    Button(options_window, text="Establecer Tiempo de Borrado del Portapapeles", command=setcopytime).pack(pady=10)
last_activity_time = None  
def reset_activity_timer(event=None):
    global last_activity_time
    last_activity_time = time.time()  
def check_for_inactivity():
    global last_activity_time, locktime
    if last_activity_time is not None:
        elapsed_time = time.time() - last_activity_time
        if elapsed_time >= locktime:
            show_lock_screen()  
    mainwindow.after(3000, check_for_inactivity)  
def show_lock_screen():
    lock_window = Toplevel(mainwindow)
    lock_window.configure(bg="#D3D3D3") 
    lock_window.attributes("-fullscreen", True)  
    lock_window.grab_set()

    Label(lock_window, text="Pantalla Bloqueada", font=("Arial", 24)).pack(pady=20)
    Label(lock_window, text="Ingrese el código para desbloquear:", font=("Arial", 16)).pack(pady=20)
    
    code_entry = Entry(lock_window, font=("Arial", 16), show="*")
    code_entry.pack(pady=20)
    
    def verify_unlock_code():
        entered_code = code_entry.get()
        if entered_code == masterkey:
            lock_window.destroy()  
            reset_activity_timer()  
        else:
            messagebox.showerror("Error", "Código incorrecto. Intente nuevamente.")
            code_entry.delete(0, "end") 

    Button(lock_window, text="Desbloquear", font=("Arial", 16), command=verify_unlock_code).pack(pady=20)
    lock_window.protocol("WM_DELETE_WINDOW", lambda: None)  
def setup_activity_detection():
    mainwindow.bind_all("<Motion>", reset_activity_timer)     
    mainwindow.bind_all("<KeyPress>", reset_activity_timer)   
    mainwindow.bind_all("<Button>", reset_activity_timer)     
    reset_activity_timer()  
    check_for_inactivity()  
def open_search_window():
    
    search_window = Toplevel(mainwindow)
    search_window.title("Buscar Datos")
    search_window.geometry("600x400")
    
    Label(search_window, text="Seleccione campo de búsqueda:").pack(pady=5)
    search_field = StringVar()
    search_field_combobox = ttk.Combobox(search_window, textvariable=search_field)
    search_field_combobox['values'] = ["id", "username", "site_name", "url", "notes","tags","extras"]
    search_field_combobox.pack(pady=5)

    Label(search_window, text="Ingrese el texto a buscar:").pack(pady=5)
    search_entry = Entry(search_window)
    search_entry.pack(pady=5)
    
    buscados = ttk.Treeview(search_window, columns=("ID", "Sitio", "Usuario", "URL","Password", "Notas","Tags","Extra1","Extra2","Extra3", "Extra4","Extra5"), show="headings")
    buscados.heading("ID", text="ID")
    buscados.heading("Sitio", text="Sitio")
    buscados.heading("Usuario", text="Usuario")
    buscados.heading("URL", text="URL")
    buscados.heading("Password",text="Password")
    buscados.heading("Notas", text="Notas")
    buscados.heading("Tags", text="Tagas")
    buscados.heading("Extra1", text="Extra1")
    buscados.heading("Extra2", text="Extra2")
    buscados.heading("Extra3", text="Extra3")
    buscados.heading("Extra4", text="Extra4")
    buscados.heading("Extra5", text="Extra5")
    buscados.pack(pady=10, fill="both", expand=True)
    hsb = ttk.Scrollbar(search_window, orient="horizontal", command=buscados.xview)
    buscados.config(xscrollcommand=hsb.set)
    hsb.pack(fill="x")

    def search():
        search_key = search_field.get()
        search_value = search_entry.get().lower()
        for row in buscados.get_children():
            buscados.delete(row)
        indx = 0    
        if search_key == "id": indx = 1
        elif search_key == "username": indx = 2
        elif search_key == "site_name": indx = 3
        elif search_key == "url": indx = 4
        elif search_key == "notes": indx = 5
        elif search_key == "tags": indx = 6
        elif search_key == "extras": indx = 7
        for entry_id, entry in alldata.items():
            if entry == "[]":
                continue
            if indx == 1: 
                if entry.pagina.id == int(search_value): 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 2: 
                if search_value in entry.pagina.username: 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 3:
                if search_value in entry.pagina.site_name: 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 4:
                if search_value in entry.pagina.url: 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 5:
                if search_value in entry.pagina.notes: 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 6:
                if search_value in entry.tags: 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))
            elif indx == 7: 
                if search_value in entry.pagina.extra_fields.extra1 or search_value in entry.pagina.extra_fields.extra2 or search_value in entry.pagina.extra_fields.extra3 or search_value in entry.pagina.extra_fields.extra4 or search_value in entry.pagina.extra_fields.extra5 : 
                    buscados.insert("", "end", values=(
                        entry.pagina.id,
                        entry.pagina.site_name,
                        entry.pagina.username,
                        entry.pagina.url,
                        entry.pagina.password,
                        entry.pagina.notes,
                        ", ".join(entry.tags),
                        entry.pagina.extra_fields.extra1,
                        entry.pagina.extra_fields.extra2,
                        entry.pagina.extra_fields.extra3,
                        entry.pagina.extra_fields.extra4,
                        entry.pagina.extra_fields.extra5
                    ))                                
    Button(search_window, text="Buscar", command=search).pack(pady=10)
def select_expiration_date():
    calendar_window = Toplevel(mainwindow)
    calendar_window.title("Seleccionar Fecha de Expiración")
    calendar = Calendar(calendar_window, selectmode='day', date_pattern="yyyy-mm-dd")
    calendar.pack(pady=10)

    def save_date():
        date = calendar.get_date()
        dateobj = datetime.strptime(date, "%Y-%m-%d")
        full_date = datetime.combine(dateobj.date(), datetime.now().time()).astimezone()
        formatted_date = full_date.isoformat()
        entry_expiration_date.delete(0, "end")
        entry_expiration_date.insert(0, formatted_date)
        calendar_window.destroy()

    Button(calendar_window, text="Guardar Fecha", command=save_date).pack(pady=10)  
mainwindow = Tk()
mainwindow.geometry("800x600")
mainwindow.title("Gestor de Contraseñas Seguras")
mainwindow.configure(bg="#D3D3D3")  
mainwindow.withdraw()
setup_activity_detection() 
fields_frame = ttk.Frame(mainwindow, padding=10)
fields_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
Label(fields_frame, text="Nuevo sitio", bg="#D3D3D3").grid(row=0, column=0, sticky="w")
entry_site = Entry(fields_frame, width=25)
entry_site.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Nombre de usuario", bg="#D3D3D3").grid(row=1, column=0, sticky="w")
entry_username = Entry(fields_frame, width=25)
entry_username.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Contraseña", bg="#D3D3D3").grid(row=2, column=0, sticky="w")
entry_password = Entry(fields_frame, show="*", width=25)
entry_password.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="URL", bg="#D3D3D3").grid(row=3, column=0, sticky="w")
entry_url = Entry(fields_frame, width=25)
entry_url.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Notas", bg="#D3D3D3").grid(row=4, column=0, sticky="w")
entry_notes = Entry(fields_frame, width=25)
entry_notes.grid(row=4, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Campo extra 1", bg="#D3D3D3").grid(row=5, column=0, sticky="w")
entry_extra1 = Entry(fields_frame, width=25)
entry_extra1.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Campo extra 2", bg="#D3D3D3").grid(row=6, column=0, sticky="w")
entry_extra2 = Entry(fields_frame, width=25)
entry_extra2.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Campo extra 3", bg="#D3D3D3").grid(row=7, column=0, sticky="w")
entry_extra3 = Entry(fields_frame, width=25)
entry_extra3.grid(row=7, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Campo extra 4", bg="#D3D3D3").grid(row=8, column=0, sticky="w")
entry_extra4 = Entry(fields_frame, width=25)
entry_extra4.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Campo extra 5", bg="#D3D3D3").grid(row=9, column=0, sticky="w")
entry_extra5 = Entry(fields_frame, width=25)
entry_extra5.grid(row=9, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Tags (separados por comas)", bg="#D3D3D3").grid(row=10, column=0, sticky="w")
entry_tags = Entry(fields_frame, width=25)
entry_tags.grid(row=10, column=1, columnspan=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Icono", bg="#D3D3D3").grid(row=11, column=0, sticky="w")
entry_icon = Entry(fields_frame, width=25)
entry_icon.grid(row=11, column=1, padx=5, pady=5, sticky="w")
Button(fields_frame, text="Seleccionar Icono", command=select_icon).grid(row=11, column=2, padx=5, pady=5, sticky="w")
Label(fields_frame, text="Fecha de Expiración", bg="#D3D3D3").grid(row=12, column=0, sticky="w")
entry_expiration_date = Entry(fields_frame, width=25)
entry_expiration_date.grid(row=12, column=1, padx=5, pady=5, sticky="w")
Button(fields_frame, text="Seleccionar Fecha", command=select_expiration_date).grid(row=12, column=2, padx=5, pady=5, sticky="w")
button_frame = ttk.Frame(mainwindow, padding=10)
button_frame.grid(row=0, column=1, padx=20, pady=20, sticky="ne")
Button(button_frame, text="Opciones", command=open_options_window).grid(row=0, column=0, pady=10, sticky="e")
Button(button_frame, text="Buscar", command=open_search_window).grid(row=1, column=0, pady=10, sticky="e")
Button(button_frame, text="Abrir ventana de encriptación/desencriptación", command=open_encryption_window).grid(row=2, column=0, pady=10, sticky="e")
Button(button_frame, text="Añadir Entrada", command=add_entry).grid(row=3, column=0, pady=10, sticky="e")
Button(button_frame, text="Desplegar Datos", command=DataDisplay).grid(row=4, column=0, pady=10, sticky="e")

initial_window()
mainwindow.mainloop()