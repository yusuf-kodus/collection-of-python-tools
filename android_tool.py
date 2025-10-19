import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import subprocess
import threading
import os
import time

class AndroidTool:
    def __init__(self):
        self.adb_path = "adb"
        self.device_connected = False
        self.current_device = None
    
    def run_adb(self, command):
        """Führt ADB-Befehl aus"""
        try:
            # Prüfe ob ADB verfügbar ist
            if command == "version":
                result = subprocess.run([self.adb_path, "version"], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(f"{self.adb_path} {command}", 
                                      capture_output=True, text=True, 
                                      shell=True, timeout=30)
            return result.stdout + result.stderr
        except FileNotFoundError:
            return "FEHLER: ADB nicht gefunden! Bitte installieren."
        except Exception as e:
            return f"Fehler: {str(e)}"
    
    def check_devices(self):
        """Prüft verbundene Geräte"""
        output = self.run_adb("devices")
        devices = []
        for line in output.split('\n')[1:]:
            line = line.strip()
            if line and '\tdevice' in line:
                device_id = line.split('\t')[0].strip()
                if device_id and device_id != 'List':
                    devices.append(device_id)
        return devices
    
    def get_device_info(self):
        """Holt Geräte-Informationen"""
        info = {}
        info['model'] = self.run_adb("shell getprop ro.product.model").strip()
        info['android'] = self.run_adb("shell getprop ro.build.version.release").strip()
        info['brand'] = self.run_adb("shell getprop ro.product.brand").strip()
        
        # Batterie-Info (Windows & Linux kompatibel)
        battery_output = self.run_adb("shell dumpsys battery")
        for line in battery_output.split('\n'):
            if 'level:' in line.lower():
                info['battery'] = line.strip()
                break
        else:
            info['battery'] = 'Batterie: N/A'
        
        return info
    
    def install_apk(self, apk_path):
        """Installiert APK"""
        return self.run_adb(f"install \"{apk_path}\"")
    
    def uninstall_app(self, package):
        """Deinstalliert App"""
        return self.run_adb(f"uninstall {package}")
    
    def list_packages(self):
        """Listet installierte Apps"""
        output = self.run_adb("shell pm list packages")
        packages = [line.replace('package:', '') for line in output.split('\n') if line.startswith('package:')]
        return packages
    
    def take_screenshot(self, save_path):
        """Macht Screenshot"""
        self.run_adb("shell screencap -p /sdcard/screenshot.png")
        self.run_adb(f"pull /sdcard/screenshot.png \"{save_path}\"")
        self.run_adb("shell rm /sdcard/screenshot.png")
        return f"Screenshot gespeichert: {save_path}"
    
    def pull_file(self, device_path, local_path):
        """Lädt Datei vom Gerät"""
        return self.run_adb(f"pull \"{device_path}\" \"{local_path}\"")
    
    def push_file(self, local_path, device_path):
        """Lädt Datei auf Gerät"""
        return self.run_adb(f"push \"{local_path}\" \"{device_path}\"")
    
    def reboot_device(self, mode=""):
        """Startet Gerät neu"""
        return self.run_adb(f"reboot {mode}")
    
    def get_logcat(self, lines=100):
        """Holt Logcat"""
        return self.run_adb(f"logcat -d -t {lines}")

class AndroidToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🤖 Android Tool - Ultimate Edition")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')
        
        self.tool = AndroidTool()
        self.auto_check_enabled = True
        self.setup_ui()
        self.check_connection()
        self.start_auto_detection()
    
    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg='#2d2d2d', height=60)
        header.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(header, text="🤖 ANDROID TOOL", font=("Arial", 20, "bold"), 
                bg='#2d2d2d', fg='#00ff00').pack(side=tk.LEFT, padx=10)
        
        self.status_label = tk.Label(header, text="⚫ Nicht verbunden", 
                                     font=("Arial", 12), bg='#2d2d2d', fg='#ff0000')
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
        self.auto_check_var = tk.BooleanVar(value=True)
        tk.Checkbutton(header, text="Auto-Erkennung", variable=self.auto_check_var,
                      bg='#2d2d2d', fg='white', selectcolor='#1e1e1e',
                      font=('Arial', 10), command=self.toggle_auto_check).pack(side=tk.RIGHT, padx=10)
        
        # Notebook (Tabs)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='white', 
                       padding=[20, 10], font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#00ff00')], 
                 foreground=[('selected', 'black')])
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tabs
        self.create_info_tab()
        self.create_apps_tab()
        self.create_files_tab()
        self.create_tools_tab()
        self.create_advanced_tab()
    
    def create_info_tab(self):
        frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(frame, text='📊 Info')
        
        tk.Button(frame, text="🔄 Gerät suchen", command=self.check_connection,
                 bg='#00ff00', fg='black', font=('Arial', 12, 'bold'),
                 padx=20, pady=10).pack(pady=20)
        
        self.info_text = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d', 
                                                   fg='white', font=('Consolas', 10))
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_apps_tab(self):
        frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(frame, text='📱 Apps')
        
        btn_frame = tk.Frame(frame, bg='#1e1e1e')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📋 Apps auflisten", command=self.list_apps,
                 bg='#2d2d2d', fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📥 APK installieren", command=self.install_apk_dialog,
                 bg='#2d2d2d', fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🗑️ App deinstallieren", command=self.uninstall_app_dialog,
                 bg='#2d2d2d', fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        self.apps_text = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d',
                                                   fg='white', font=('Consolas', 9))
        self.apps_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_files_tab(self):
        frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(frame, text='📁 Dateien')
        
        btn_frame = tk.Frame(frame, bg='#1e1e1e')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📥 Datei herunterladen", command=self.pull_file_dialog,
                 bg='#2d2d2d', fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📤 Datei hochladen", command=self.push_file_dialog,
                 bg='#2d2d2d', fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        self.files_text = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d',
                                                    fg='white', font=('Consolas', 10))
        self.files_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_tools_tab(self):
        frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(frame, text='🛠️ Tools')
        
        btn_frame = tk.Frame(frame, bg='#1e1e1e')
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="📸 Screenshot", command=self.take_screenshot,
                 bg='#2d2d2d', fg='white', padx=20, pady=10, width=15).grid(row=0, column=0, padx=10, pady=10)
        
        tk.Button(btn_frame, text="🔄 Neustart", command=self.reboot_normal,
                 bg='#2d2d2d', fg='white', padx=20, pady=10, width=15).grid(row=0, column=1, padx=10, pady=10)
        
        tk.Button(btn_frame, text="⚡ Recovery", command=self.reboot_recovery,
                 bg='#2d2d2d', fg='white', padx=20, pady=10, width=15).grid(row=1, column=0, padx=10, pady=10)
        
        tk.Button(btn_frame, text="🔧 Bootloader", command=self.reboot_bootloader,
                 bg='#2d2d2d', fg='white', padx=20, pady=10, width=15).grid(row=1, column=1, padx=10, pady=10)
        
        self.tools_text = scrolledtext.ScrolledText(frame, height=15, bg='#2d2d2d',
                                                    fg='white', font=('Consolas', 10))
        self.tools_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def create_advanced_tab(self):
        frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(frame, text='⚙️ Erweitert')
        
        tk.Label(frame, text="ADB Befehl:", bg='#1e1e1e', fg='white',
                font=('Arial', 12)).pack(pady=10)
        
        self.cmd_entry = tk.Entry(frame, bg='#2d2d2d', fg='white', 
                                 font=('Consolas', 11), width=60)
        self.cmd_entry.pack(pady=5)
        
        tk.Button(frame, text="▶️ Ausführen", command=self.run_custom_command,
                 bg='#00ff00', fg='black', font=('Arial', 11, 'bold'),
                 padx=30, pady=10).pack(pady=10)
        
        tk.Button(frame, text="📋 Logcat anzeigen", command=self.show_logcat,
                 bg='#2d2d2d', fg='white', padx=20, pady=8).pack(pady=5)
        
        self.advanced_text = scrolledtext.ScrolledText(frame, height=15, bg='#2d2d2d',
                                                       fg='white', font=('Consolas', 9))
        self.advanced_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def check_connection(self):
        def check():
            try:
                self.log_info("Suche nach Geräten...\n")
                
                # Suche Geräte
                devices = self.tool.check_devices()
                
                if devices:
                    self.tool.device_connected = True
                    self.tool.current_device = devices[0]
                    self.status_label.config(text=f"🟢 Verbunden: {devices[0]}", fg='#00ff00')
                    
                    self.log_info("✓ Gerät gefunden!\n\nLade Informationen...\n")
                    info = self.tool.get_device_info()
                    
                    self.log_info(f"\n✓ Gerät verbunden!\n\n"
                                f"Seriennummer: {devices[0]}\n"
                                f"Modell: {info.get('model', 'N/A')}\n"
                                f"Marke: {info.get('brand', 'N/A')}\n"
                                f"Android: {info.get('android', 'N/A')}\n"
                                f"{info.get('battery', 'Batterie: N/A')}\n")
                else:
                    self.tool.device_connected = False
                    self.status_label.config(text="⚫ Nicht verbunden", fg='#ff0000')
                    
                    # Zeige detaillierte Diagnose
                    raw_output = self.tool.run_adb("devices")
                    
                    self.log_info(f"\n✗ Kein Gerät gefunden\n\n"
                                f"ADB Output:\n{raw_output}\n\n"
                                f"CHECKLISTE:\n"
                                f"□ USB-Kabel eingesteckt?\n"
                                f"□ USB-Debugging aktiviert?\n"
                                f"   (Einstellungen → Entwickleroptionen)\n"
                                f"□ 'USB-Debugging erlauben' bestätigt?\n"
                                f"□ Anderes USB-Kabel probieren?\n"
                                f"□ USB-Port wechseln?\n\n"
                                f"ENTWICKLEROPTIONEN AKTIVIEREN:\n"
                                f"1. Einstellungen → Über das Telefon\n"
                                f"2. 7x auf 'Build-Nummer' tippen\n"
                                f"3. Zurück → Entwickleroptionen\n"
                                f"4. USB-Debugging aktivieren\n")
            
            except Exception as e:
                self.tool.device_connected = False
                self.status_label.config(text="⚫ Fehler", fg='#ff0000')
                self.log_info(f"\n✗ Fehler beim Suchen:\n{str(e)}\n\n"
                            f"Versuche:\n"
                            f"1. Tool neu starten\n"
                            f"2. USB-Kabel neu einstecken\n"
                            f"3. Handy neu starten\n")
        
        threading.Thread(target=check, daemon=True).start()
    
    def list_apps(self):
        def list_apps_thread():
            self.apps_text.delete(1.0, tk.END)
            self.apps_text.insert(tk.END, "Lade Apps...\n\n")
            
            packages = self.tool.list_packages()
            self.apps_text.delete(1.0, tk.END)
            self.apps_text.insert(tk.END, f"📱 {len(packages)} Apps gefunden:\n\n")
            
            for i, pkg in enumerate(packages[:100], 1):
                self.apps_text.insert(tk.END, f"{i}. {pkg}\n")
        
        threading.Thread(target=list_apps_thread, daemon=True).start()
    
    def install_apk_dialog(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        apk_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")])
        if apk_path:
            def install():
                self.apps_text.insert(tk.END, f"\n📥 Installiere {os.path.basename(apk_path)}...\n")
                self.apps_text.update()
                result = self.tool.install_apk(apk_path)
                self.apps_text.insert(tk.END, result + "\n")
                if 'Success' in result:
                    messagebox.showinfo("Erfolg", "APK erfolgreich installiert!")
            threading.Thread(target=install, daemon=True).start()
    
    def uninstall_app_dialog(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        package = simpledialog.askstring("Deinstallieren", "Package Name (z.B. com.example.app):")
        if package:
            def uninstall():
                self.apps_text.insert(tk.END, f"\n🗑️ Deinstalliere {package}...\n")
                self.apps_text.update()
                result = self.tool.uninstall_app(package)
                self.apps_text.insert(tk.END, result + "\n")
                if 'Success' in result:
                    messagebox.showinfo("Erfolg", "App deinstalliert!")
            threading.Thread(target=uninstall, daemon=True).start()
    
    def pull_file_dialog(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        device_path = simpledialog.askstring("Download", "Gerätepfad (z.B. /sdcard/Download/file.txt):")
        if device_path:
            local_path = filedialog.asksaveasfilename(defaultextension=".*")
            if local_path:
                def pull():
                    self.files_text.insert(tk.END, f"\n📥 Lade {device_path}...\n")
                    self.files_text.update()
                    result = self.tool.pull_file(device_path, local_path)
                    self.files_text.insert(tk.END, result + "\n")
                    if os.path.exists(local_path):
                        messagebox.showinfo("Erfolg", f"Datei gespeichert:\n{local_path}")
                threading.Thread(target=pull, daemon=True).start()
    
    def push_file_dialog(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        local_path = filedialog.askopenfilename()
        if local_path:
            device_path = simpledialog.askstring("Upload", "Zielpfad auf Gerät (z.B. /sdcard/Download/):")
            if device_path:
                def push():
                    self.files_text.insert(tk.END, f"\n📤 Lade {os.path.basename(local_path)} hoch...\n")
                    self.files_text.update()
                    result = self.tool.push_file(local_path, device_path)
                    self.files_text.insert(tk.END, result + "\n")
                    if 'pushed' in result.lower():
                        messagebox.showinfo("Erfolg", "Datei hochgeladen!")
                threading.Thread(target=push, daemon=True).start()
    
    def take_screenshot(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        def screenshot():
            save_path = os.path.join(os.getcwd(), f"screenshot_{int(time.time())}.png")
            self.tools_text.insert(tk.END, "\n📸 Mache Screenshot...\n")
            self.tools_text.update()
            result = self.tool.take_screenshot(save_path)
            self.tools_text.insert(tk.END, f"{result}\n")
            if os.path.exists(save_path):
                messagebox.showinfo("Screenshot", f"Gespeichert:\n{save_path}")
                os.startfile(save_path)
        threading.Thread(target=screenshot, daemon=True).start()
    
    def reboot_normal(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        if messagebox.askyesno("Neustart", "Gerät neu starten?"):
            self.tool.reboot_device()
            self.tools_text.insert(tk.END, "\n🔄 Gerät wird neu gestartet...\n")
            self.tool.device_connected = False
            self.status_label.config(text="⚫ Nicht verbunden", fg='#ff0000')
    
    def reboot_recovery(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        if messagebox.askyesno("Recovery", "In Recovery-Modus starten?\n\nWARNUNG: Nur für fortgeschrittene Nutzer!"):
            self.tool.reboot_device("recovery")
            self.tools_text.insert(tk.END, "\n⚡ Starte in Recovery...\n")
            self.tool.device_connected = False
            self.status_label.config(text="⚫ Nicht verbunden", fg='#ff0000')
    
    def reboot_bootloader(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        if messagebox.askyesno("Bootloader", "In Bootloader starten?\n\nWARNUNG: Nur für fortgeschrittene Nutzer!"):
            self.tool.reboot_device("bootloader")
            self.tools_text.insert(tk.END, "\n🔧 Starte in Bootloader...\n")
            self.tool.device_connected = False
            self.status_label.config(text="⚫ Nicht verbunden", fg='#ff0000')
    
    def run_custom_command(self):
        cmd = self.cmd_entry.get().strip()
        if cmd:
            def run():
                self.advanced_text.insert(tk.END, f"\n$ adb {cmd}\n")
                self.advanced_text.update()
                result = self.tool.run_adb(cmd)
                self.advanced_text.insert(tk.END, result + "\n")
                self.cmd_entry.delete(0, tk.END)
            threading.Thread(target=run, daemon=True).start()
        else:
            messagebox.showwarning("Warnung", "Bitte Befehl eingeben!")
    
    def show_logcat(self):
        if not self.tool.device_connected:
            messagebox.showerror("Fehler", "Kein Gerät verbunden!")
            return
        
        def get_logcat():
            self.advanced_text.delete(1.0, tk.END)
            self.advanced_text.insert(tk.END, "Lade Logcat...\n\n")
            self.advanced_text.update()
            result = self.tool.get_logcat(200)
            self.advanced_text.delete(1.0, tk.END)
            self.advanced_text.insert(tk.END, result)
        threading.Thread(target=get_logcat, daemon=True).start()
    
    def log_info(self, text):
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, text)
    
    def toggle_auto_check(self):
        self.auto_check_enabled = self.auto_check_var.get()
        if self.auto_check_enabled:
            self.start_auto_detection()
    
    def start_auto_detection(self):
        """Startet automatische USB-Erkennung"""
        def auto_detect():
            while self.auto_check_enabled:
                try:
                    # Prüfe nur wenn nicht verbunden
                    if not self.tool.device_connected:
                        devices = self.tool.check_devices()
                        
                        if devices:
                            # Gerät gefunden - automatisch verbinden
                            self.tool.device_connected = True
                            self.tool.current_device = devices[0]
                            self.status_label.config(text=f"🟢 Verbunden: {devices[0]}", fg='#00ff00')
                            
                            # Zeige Info
                            info = self.tool.get_device_info()
                            self.log_info(f"\n✓ Gerät automatisch erkannt!\n\n"
                                        f"Seriennummer: {devices[0]}\n"
                                        f"Modell: {info.get('model', 'N/A')}\n"
                                        f"Marke: {info.get('brand', 'N/A')}\n"
                                        f"Android: {info.get('android', 'N/A')}\n"
                                        f"{info.get('battery', 'Batterie: N/A')}\n\n"
                                        f"Bereit für Befehle!\n")
                    
                    # Warte 3 Sekunden vor nächster Prüfung
                    time.sleep(3)
                    
                except:
                    time.sleep(3)
        
        threading.Thread(target=auto_detect, daemon=True).start()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        
        # Zeige Splash-Screen
        splash = tk.Toplevel()
        splash.title("Android Tool")
        splash.geometry("400x200")
        splash.configure(bg='#1e1e1e')
        splash.overrideredirect(True)
        
        # Zentriere Splash
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() // 2) - (400 // 2)
        y = (splash.winfo_screenheight() // 2) - (200 // 2)
        splash.geometry(f"400x200+{x}+{y}")
        
        tk.Label(splash, text="🤖 ANDROID TOOL", font=("Arial", 24, "bold"),
                bg='#1e1e1e', fg='#00ff00').pack(pady=30)
        tk.Label(splash, text="Initialisiere...\nPrüfe USB-Verbindung...",
                font=("Arial", 12), bg='#1e1e1e', fg='white').pack(pady=20)
        
        splash.update()
        
        # Lade Hauptfenster
        def load_main():
            time.sleep(1)
            splash.destroy()
            app = AndroidToolGUI(root)
        
        threading.Thread(target=load_main, daemon=True).start()
        
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Fehler", f"Kritischer Fehler:\n{str(e)}")
        raise
