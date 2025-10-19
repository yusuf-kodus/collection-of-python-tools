import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import paramiko
import threading
import time
import subprocess
import re

class ChromeOSRemote:
    def __init__(self):
        self.ssh = None
        self.connected = False
        self.hostname = None
        
    def connect(self, hostname, username, password):
        """Verbindet mit ChromeOS über SSH"""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname, username=username, password=password, timeout=10)
            self.connected = True
            self.hostname = hostname
            return True
        except Exception as e:
            return False
    
    def disconnect(self):
        """Trennt Verbindung"""
        if self.ssh:
            self.ssh.close()
            self.connected = False
    
    def execute_command(self, command):
        """Führt Befehl auf ChromeOS aus"""
        if not self.connected:
            return None
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            return output if output else error
        except:
            return None
    
    def get_system_info(self):
        """Holt System-Informationen"""
        info = {}
        info['hostname'] = self.execute_command('hostname')
        info['uptime'] = self.execute_command('uptime')
        info['memory'] = self.execute_command('free -h')
        info['disk'] = self.execute_command('df -h')
        info['cpu'] = self.execute_command('lscpu | grep "Model name"')
        return info
    
    def get_processes(self):
        """Holt laufende Prozesse"""
        return self.execute_command('ps aux --sort=-%cpu | head -20')
    
    def kill_process(self, pid):
        """Beendet Prozess"""
        return self.execute_command(f'kill -9 {pid}')
    
    def restart_chrome(self):
        """Startet Chrome neu"""
        return self.execute_command('pkill chrome && google-chrome &')
    
    def clear_chrome_cache(self):
        """Löscht Chrome Cache"""
        return self.execute_command('rm -rf ~/.cache/google-chrome/*')
    
    def take_screenshot(self, save_path):
        """Macht Screenshot"""
        try:
            self.execute_command('gnome-screenshot -f /tmp/screenshot.png')
            sftp = self.ssh.open_sftp()
            sftp.get('/tmp/screenshot.png', save_path)
            sftp.close()
            return True
        except:
            return False
    
    def get_chrome_tabs(self):
        """Zeigt offene Chrome-Tabs"""
        return self.execute_command('wmctrl -l | grep Chrome')
    
    def open_url(self, url):
        """Öffnet URL in Chrome"""
        return self.execute_command(f'google-chrome "{url}" &')
    
    def shutdown(self):
        """Fährt ChromeOS herunter"""
        return self.execute_command('sudo shutdown now')
    
    def reboot(self):
        """Startet ChromeOS neu"""
        return self.execute_command('sudo reboot')
    
    def get_network_info(self):
        """Netzwerk-Informationen"""
        return self.execute_command('ip addr show && iwconfig')
    
    def get_battery(self):
        """Batterie-Status"""
        return self.execute_command('upower -i /org/freedesktop/UPower/devices/battery_BAT0')
    
    def list_files(self, path='/home'):
        """Listet Dateien"""
        return self.execute_command(f'ls -lah {path}')
    
    def download_file(self, remote_path, local_path):
        """Lädt Datei herunter"""
        try:
            sftp = self.ssh.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except:
            return False
    
    def upload_file(self, local_path, remote_path):
        """Lädt Datei hoch"""
        try:
            sftp = self.ssh.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except:
            return False
    
    def install_package(self, package):
        """Installiert Paket"""
        return self.execute_command(f'sudo apt install -y {package}')
    
    def get_installed_apps(self):
        """Zeigt installierte Apps"""
        return self.execute_command('dpkg -l | grep ^ii')

class ChromeOSRemoteGUI:
    def __init__(self):
        self.remote = ChromeOSRemote()
        
        self.window = tk.Tk()
        self.window.title("ChromeOS Remote Control")
        self.window.geometry("1000x750")
        self.window.configure(bg="#1a1a1a")
        
        # Header
        header = tk.Frame(self.window, bg="#2d2d2d", height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        tk.Label(header, text="🖥️ ChromeOS Remote Control", font=("Arial", 18, "bold"),
                bg="#2d2d2d", fg="#00bfff").pack(side="left", padx=20, pady=15)
        
        self.status_label = tk.Label(header, text="● Nicht verbunden", font=("Arial", 11),
                                     bg="#2d2d2d", fg="#ff5555")
        self.status_label.pack(side="right", padx=20)
        
        # Connection Frame
        conn_frame = tk.LabelFrame(self.window, text="Verbindung", bg="#1a1a1a", fg="white",
                                   font=("Arial", 11, "bold"))
        conn_frame.pack(fill="x", padx=20, pady=10)
        
        inner = tk.Frame(conn_frame, bg="#1a1a1a")
        inner.pack(pady=10)
        
        tk.Label(inner, text="IP/Hostname:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=0, column=0, padx=5)
        self.host_entry = tk.Entry(inner, width=20, font=("Arial", 10))
        self.host_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(inner, text="Benutzer:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=0, column=2, padx=5)
        self.user_entry = tk.Entry(inner, width=15, font=("Arial", 10))
        self.user_entry.insert(0, "chronos")
        self.user_entry.grid(row=0, column=3, padx=5)
        
        tk.Label(inner, text="Passwort:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=0, column=4, padx=5)
        self.pass_entry = tk.Entry(inner, width=15, font=("Arial", 10), show="*")
        self.pass_entry.grid(row=0, column=5, padx=5)
        
        self.connect_btn = tk.Button(inner, text="🔌 Verbinden", command=self.connect,
                                     bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.connect_btn.grid(row=0, column=6, padx=10)
        
        tk.Button(inner, text="🔍 USB-Suche", command=self.auto_find_usb,
                 bg="#FF9800", fg="white", font=("Arial", 9, "bold")).grid(row=1, column=0, columnspan=4, pady=5, sticky="ew", padx=5)
        
        tk.Button(inner, text="📡 Netzwerk-Scan", command=self.scan_network,
                 bg="#9C27B0", fg="white", font=("Arial", 9, "bold")).grid(row=1, column=4, columnspan=3, pady=5, sticky="ew", padx=5)
        
        # Tabs
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: System
        tab1 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab1, text="System")
        self.create_system_tab(tab1)
        
        # Tab 2: Prozesse
        tab2 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab2, text="Prozesse")
        self.create_process_tab(tab2)
        
        # Tab 3: Chrome
        tab3 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab3, text="Chrome")
        self.create_chrome_tab(tab3)
        
        # Tab 4: Dateien
        tab4 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab4, text="Dateien")
        self.create_files_tab(tab4)
        
        # Tab 5: Steuerung
        tab5 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab5, text="Steuerung")
        self.create_control_tab(tab5)
        
        self.window.mainloop()
    
    def create_system_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📊 System-Info", command=self.get_system_info,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🔋 Batterie", command=self.get_battery,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🌐 Netzwerk", command=self.get_network,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        
        self.system_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                      font=("Consolas", 9))
        self.system_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_process_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔄 Prozesse laden", command=self.get_processes,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="❌ Prozess beenden", command=self.kill_process,
                 bg="#f44336", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        
        self.process_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                       font=("Consolas", 9))
        self.process_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_chrome_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔄 Chrome neustarten", command=self.restart_chrome,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🗑️ Cache löschen", command=self.clear_cache,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🌐 URL öffnen", command=self.open_url,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        
        self.chrome_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                      font=("Consolas", 9))
        self.chrome_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_files_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📁 Dateien anzeigen", command=self.list_files,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📥 Datei herunterladen", command=self.download_file,
                 bg="#00BCD4", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📤 Datei hochladen", command=self.upload_file,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        
        self.files_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                     font=("Consolas", 9))
        self.files_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_control_tab(self, parent):
        info = tk.Label(parent, text="⚠️ System-Steuerung", bg="#1a1a1a", fg="#ff9800",
                       font=("Arial", 14, "bold"))
        info.pack(pady=20)
        
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="🔄 Neustart", command=self.reboot,
                 bg="#FF9800", fg="white", font=("Arial", 11, "bold"), width=20, height=2).pack(pady=10)
        tk.Button(btn_frame, text="⚡ Herunterfahren", command=self.shutdown,
                 bg="#f44336", fg="white", font=("Arial", 11, "bold"), width=20, height=2).pack(pady=10)
        tk.Button(btn_frame, text="📸 Screenshot", command=self.take_screenshot,
                 bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), width=20, height=2).pack(pady=10)
        
        self.control_text = scrolledtext.ScrolledText(parent, height=10, bg="#2d2d2d", fg="#ffff00",
                                                       font=("Consolas", 10))
        self.control_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def connect(self):
        host = self.host_entry.get()
        user = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not host or not user or not password:
            messagebox.showwarning("Warnung", "Alle Felder ausfüllen!")
            return
        
        if self.remote.connect(host, user, password):
            self.status_label.config(text=f"● Verbunden mit {host}", fg="#00ff00")
            self.connect_btn.config(text="❌ Trennen", bg="#f44336")
            messagebox.showinfo("Erfolg", f"Mit {host} verbunden!")
        else:
            messagebox.showerror("Fehler", "Verbindung fehlgeschlagen!\n\nStelle sicher:\n- SSH ist aktiviert\n- IP/Hostname korrekt\n- Passwort richtig")
    
    def get_system_info(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.system_text.delete(1.0, tk.END)
        self.system_text.insert(tk.END, "Lade System-Informationen...\n\n")
        
        info = self.remote.get_system_info()
        for key, value in info.items():
            self.system_text.insert(tk.END, f"=== {key.upper()} ===\n{value}\n\n")
    
    def get_battery(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.system_text.delete(1.0, tk.END)
        battery = self.remote.get_battery()
        self.system_text.insert(tk.END, "=== BATTERIE ===\n\n")
        self.system_text.insert(tk.END, battery)
    
    def get_network(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.system_text.delete(1.0, tk.END)
        network = self.remote.get_network_info()
        self.system_text.insert(tk.END, "=== NETZWERK ===\n\n")
        self.system_text.insert(tk.END, network)
    
    def get_processes(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.process_text.delete(1.0, tk.END)
        processes = self.remote.get_processes()
        self.process_text.insert(tk.END, "=== TOP PROZESSE ===\n\n")
        self.process_text.insert(tk.END, processes)
    
    def kill_process(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        pid = simpledialog.askinteger("Prozess beenden", "PID eingeben:")
        if pid:
            self.remote.kill_process(pid)
            messagebox.showinfo("Erfolg", f"Prozess {pid} beendet!")
    
    def restart_chrome(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.remote.restart_chrome()
        self.chrome_text.delete(1.0, tk.END)
        self.chrome_text.insert(tk.END, "✓ Chrome wird neugestartet...\n")
    
    def clear_cache(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.remote.clear_chrome_cache()
        self.chrome_text.delete(1.0, tk.END)
        self.chrome_text.insert(tk.END, "✓ Chrome Cache gelöscht!\n")
    
    def open_url(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        url = simpledialog.askstring("URL öffnen", "URL eingeben:")
        if url:
            self.remote.open_url(url)
            self.chrome_text.delete(1.0, tk.END)
            self.chrome_text.insert(tk.END, f"✓ Öffne: {url}\n")
    
    def list_files(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        path = simpledialog.askstring("Pfad", "Pfad eingeben:", initialvalue="/home")
        if path:
            files = self.remote.list_files(path)
            self.files_text.delete(1.0, tk.END)
            self.files_text.insert(tk.END, f"=== DATEIEN IN {path} ===\n\n")
            self.files_text.insert(tk.END, files)
    
    def download_file(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        remote = simpledialog.askstring("Download", "Remote-Pfad:")
        if remote:
            from tkinter import filedialog
            local = filedialog.asksaveasfilename()
            if local:
                if self.remote.download_file(remote, local):
                    messagebox.showinfo("Erfolg", "Datei heruntergeladen!")
    
    def upload_file(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        from tkinter import filedialog
        local = filedialog.askopenfilename()
        if local:
            remote = simpledialog.askstring("Upload", "Remote-Pfad:")
            if remote:
                if self.remote.upload_file(local, remote):
                    messagebox.showinfo("Erfolg", "Datei hochgeladen!")
    
    def reboot(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        if messagebox.askyesno("Bestätigung", "ChromeOS wirklich neustarten?"):
            self.remote.reboot()
            self.control_text.insert(tk.END, "✓ Neustart wird durchgeführt...\n")
    
    def shutdown(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        if messagebox.askyesno("Bestätigung", "ChromeOS wirklich herunterfahren?"):
            self.remote.shutdown()
            self.control_text.insert(tk.END, "✓ System wird heruntergefahren...\n")
    
    def take_screenshot(self):
        if not self.remote.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        from tkinter import filedialog
        save_path = filedialog.asksaveasfilename(defaultextension=".png")
        if save_path:
            if self.remote.take_screenshot(save_path):
                messagebox.showinfo("Erfolg", f"Screenshot gespeichert:\n{save_path}")
    
    def auto_find_usb(self):
        """Sucht automatisch nach USB-verbundenen Chromebooks"""
        self.control_text.delete(1.0, tk.END)
        self.control_text.insert(tk.END, "Suche nach USB-Geräten via ADB...\n\n")
        
        # Versuche ADB mit vollem Pfad
        adb_paths = [
            'adb',
            'adb.exe',
            r'C:\platform-tools\adb.exe',
            r'C:\adb\adb.exe',
            r'C:\Android\platform-tools\adb.exe'
        ]
        
        adb_cmd = None
        for path in adb_paths:
            try:
                test = subprocess.run([path, 'version'], capture_output=True, timeout=2)
                if test.returncode == 0:
                    adb_cmd = path
                    self.control_text.insert(tk.END, f"✓ ADB gefunden: {path}\n\n")
                    break
            except:
                continue
        
        if not adb_cmd:
            self.control_text.insert(tk.END, "❌ ADB nicht gefunden!\n\n")
            self.control_text.insert(tk.END, "Lösungen:\n")
            self.control_text.insert(tk.END, "1. ADB zu PATH hinzufügen\n")
            self.control_text.insert(tk.END, "2. ADB nach C:\\platform-tools\\ entpacken\n")
            self.control_text.insert(tk.END, "3. CMD neu starten nach Installation\n")
            messagebox.showerror("ADB nicht gefunden", "ADB ist installiert aber nicht im PATH!\n\nLösung:\n1. Windows-Taste + R\n2. 'sysdm.cpl' eingeben\n3. Erweitert → Umgebungsvariablen\n4. Path bearbeiten\n5. ADB-Pfad hinzufügen\n6. Tool neu starten")
            return
        
        try:
            result = subprocess.run([adb_cmd, 'devices'], capture_output=True, text=True, timeout=5)
            devices = []
            for line in result.stdout.split('\n')[1:]:
                if '\t' in line and 'device' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
            
            if devices:
                self.control_text.insert(tk.END, f"=== GEFUNDENE USB-GERÄTE ({len(devices)}) ===\n\n")
                for i, device in enumerate(devices, 1):
                    self.control_text.insert(tk.END, f"[{i}] {device}\n")
                    
                    # Versuche IP zu holen
                    try:
                        ip_result = subprocess.run([adb_cmd, '-s', device, 'shell', 'ip', 'addr', 'show', 'wlan0'],
                                                  capture_output=True, text=True, timeout=5)
                        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
                        if ip_match:
                            ip = ip_match.group(1)
                            self.control_text.insert(tk.END, f"    IP: {ip}\n")
                            self.host_entry.delete(0, tk.END)
                            self.host_entry.insert(0, ip)
                            self.control_text.insert(tk.END, f"    ✓ IP eingetragen\n")
                    except:
                        pass
                    self.control_text.insert(tk.END, "\n")
                
                messagebox.showinfo("USB-Suche", f"{len(devices)} Gerät(e) gefunden!")
            else:
                self.control_text.insert(tk.END, "❌ Keine USB-Geräte gefunden!\n\n")
                self.control_text.insert(tk.END, "Stelle sicher:\n")
                self.control_text.insert(tk.END, "- ADB ist installiert\n")
                self.control_text.insert(tk.END, "- USB-Debugging aktiviert\n")
                self.control_text.insert(tk.END, "- Chromebook per USB verbunden\n")
                messagebox.showwarning("USB-Suche", "Keine Geräte gefunden!")
        except FileNotFoundError:
            self.control_text.insert(tk.END, "❌ ADB nicht gefunden!\n\n")
            self.control_text.insert(tk.END, "ADB installieren:\n")
            self.control_text.insert(tk.END, "https://developer.android.com/studio/releases/platform-tools\n")
            messagebox.showerror("Fehler", "ADB nicht installiert!\n\nDownload:\nhttps://developer.android.com/studio/releases/platform-tools")
        except Exception as e:
            self.control_text.insert(tk.END, f"❌ Fehler: {str(e)}\n")
    
    def scan_network(self):
        """Scannt Netzwerk nach Chromebooks"""
        self.control_text.delete(1.0, tk.END)
        self.control_text.insert(tk.END, "Scanne Netzwerk (kann dauern)...\n\n")
        
        def scan():
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', result.stdout)
                
                chromebooks = []
                for ip in set(ips):
                    try:
                        test_ssh = paramiko.SSHClient()
                        test_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        test_ssh.connect(ip, username='chronos', password='test', timeout=2)
                        chromebooks.append(ip)
                        test_ssh.close()
                    except paramiko.AuthenticationException:
                        chromebooks.append(ip)
                    except:
                        pass
                
                if chromebooks:
                    self.control_text.insert(tk.END, f"=== GEFUNDENE GERÄTE ({len(chromebooks)}) ===\n\n")
                    for i, ip in enumerate(chromebooks, 1):
                        self.control_text.insert(tk.END, f"[{i}] {ip}\n")
                    
                    self.host_entry.delete(0, tk.END)
                    self.host_entry.insert(0, chromebooks[0])
                    self.control_text.insert(tk.END, f"\n✓ {chromebooks[0]} eingetragen\n")
                    messagebox.showinfo("Netzwerk-Scan", f"{len(chromebooks)} Gerät(e) gefunden!")
                else:
                    self.control_text.insert(tk.END, "❌ Keine Geräte gefunden!\n")
                    messagebox.showinfo("Netzwerk-Scan", "Keine Geräte gefunden.")
            except Exception as e:
                self.control_text.insert(tk.END, f"❌ Fehler: {str(e)}\n")
        
        threading.Thread(target=scan, daemon=True).start()

if __name__ == "__main__":
    ChromeOSRemoteGUI()
