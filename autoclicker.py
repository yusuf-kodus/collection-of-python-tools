import tkinter as tk
from tkinter import ttk
import pyautogui
import threading
import time
import keyboard

class AutoClicker:
    def __init__(self):
        self.running = False
        self.thread = None
        
        self.window = tk.Tk()
        self.window.title("AutoClicker")
        self.window.geometry("400x550")
        self.window.resizable(False, False)
        self.window.configure(bg="#2b2b2b")
        
        # Titel
        title = tk.Label(self.window, text="🖱️ AutoClicker", font=("Arial", 20, "bold"), 
                        bg="#2b2b2b", fg="white")
        title.pack(pady=15)
        
        # Klick-Intervall
        frame1 = tk.Frame(self.window, bg="#2b2b2b")
        frame1.pack(pady=10)
        tk.Label(frame1, text="Intervall (Sekunden):", bg="#2b2b2b", fg="white", 
                font=("Arial", 11)).pack()
        self.interval_var = tk.DoubleVar(value=0.1)
        interval_spin = tk.Spinbox(frame1, from_=0.01, to=10, increment=0.01, 
                                   textvariable=self.interval_var, width=15, font=("Arial", 12))
        interval_spin.pack(pady=5)
        
        # Mausbutton
        frame2 = tk.Frame(self.window, bg="#2b2b2b")
        frame2.pack(pady=10)
        tk.Label(frame2, text="Mausbutton:", bg="#2b2b2b", fg="white", 
                font=("Arial", 11)).pack()
        self.button_var = tk.StringVar(value="left")
        button_combo = ttk.Combobox(frame2, textvariable=self.button_var, 
                                    values=["left", "right", "middle"], 
                                    state="readonly", width=13, font=("Arial", 11))
        button_combo.pack(pady=5)
        
        # Klick-Typ
        frame3 = tk.Frame(self.window, bg="#2b2b2b")
        frame3.pack(pady=10)
        tk.Label(frame3, text="Klick-Typ:", bg="#2b2b2b", fg="white", 
                font=("Arial", 11)).pack()
        self.click_type_var = tk.StringVar(value="single")
        click_combo = ttk.Combobox(frame3, textvariable=self.click_type_var, 
                                   values=["single", "double"], 
                                   state="readonly", width=13, font=("Arial", 11))
        click_combo.pack(pady=5)
        
        # Anzahl Klicks (0 = unendlich)
        frame4 = tk.Frame(self.window, bg="#2b2b2b")
        frame4.pack(pady=10)
        tk.Label(frame4, text="Anzahl Klicks (0 = ∞):", bg="#2b2b2b", fg="white", 
                font=("Arial", 11)).pack()
        self.count_var = tk.IntVar(value=0)
        count_spin = tk.Spinbox(frame4, from_=0, to=100000, increment=1, 
                               textvariable=self.count_var, width=15, font=("Arial", 12))
        count_spin.pack(pady=5)
        
        # Button Frame
        btn_frame = tk.Frame(self.window, bg="#2b2b2b")
        btn_frame.pack(pady=15)
        
        # Start Button
        self.start_btn = tk.Button(btn_frame, text="▶ START", command=self.start,
                                   font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
                                   width=10, height=2, cursor="hand2", relief="flat")
        self.start_btn.grid(row=0, column=0, padx=5)
        
        # Stop Button
        self.stop_btn = tk.Button(btn_frame, text="⏸ STOP", command=self.stop,
                                  font=("Arial", 12, "bold"), bg="#f44336", fg="white",
                                  width=10, height=2, cursor="hand2", relief="flat", state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        # Not-Aus Button
        self.emergency_btn = tk.Button(self.window, text="🚨 NOT-AUS", command=self.emergency_stop,
                                       font=("Arial", 14, "bold"), bg="#ff0000", fg="white",
                                       width=20, height=2, cursor="hand2", relief="raised", bd=3)
        self.emergency_btn.pack(pady=10)
        
        # Status
        self.status_label = tk.Label(self.window, text="Status: Gestoppt", 
                                     bg="#2b2b2b", fg="#ff5555", font=("Arial", 10))
        self.status_label.pack()
        
        # Hotkey Info
        info = tk.Label(self.window, text="Hotkeys: F6=Start/Stop | ESC=Not-Aus", 
                       bg="#2b2b2b", fg="#888888", font=("Arial", 9))
        info.pack(pady=5)
        
        # Hotkeys registrieren
        keyboard.add_hotkey('f6', self.toggle)
        keyboard.add_hotkey('esc', self.emergency_stop)
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.mainloop()
    
    def toggle(self):
        if self.running:
            self.stop()
        else:
            self.start()
    
    def start(self):
        if not self.running:
            self.running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_label.config(text="Status: Läuft...", fg="#4CAF50")
            self.thread = threading.Thread(target=self.click_loop, daemon=True)
            self.thread.start()
    
    def stop(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Gestoppt", fg="#ff5555")
    
    def emergency_stop(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: NOT-AUS aktiviert!", fg="#ff0000")
        pyautogui.moveRel(0, 0)  # Maus kurz bewegen um Klicks zu unterbrechen
    
    def click_loop(self):
        interval = self.interval_var.get()
        button = self.button_var.get()
        click_type = self.click_type_var.get()
        count = self.count_var.get()
        clicks = 2 if click_type == "double" else 1
        
        counter = 0
        while self.running:
            if count > 0 and counter >= count:
                self.stop()
                break
            
            pyautogui.click(button=button, clicks=clicks)
            counter += 1
            time.sleep(interval)
    
    def on_close(self):
        self.running = False
        keyboard.unhook_all()
        self.window.destroy()

if __name__ == "__main__":
    AutoClicker()
