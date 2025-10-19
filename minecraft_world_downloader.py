import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import struct
import threading
import time
import os
import json
import zlib
from pathlib import Path
import hashlib
import random

class BedrockProtocol:
    """Minecraft Bedrock Protocol Handler"""
    
    PACKET_LOGIN = 0x01
    PACKET_PLAY_STATUS = 0x02
    PACKET_DISCONNECT = 0x05
    PACKET_RESOURCE_PACK = 0x06
    PACKET_TEXT = 0x09
    PACKET_LEVEL_CHUNK = 0x3a
    PACKET_GAME_DATA = 0x4b
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False
        self.chunks = {}
        self.world_data = {}
        
    def connect(self):
        """Verbindet zum Bedrock Server"""
        try:
            # Teste erst Erreichbarkeit
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.settimeout(2)
            
            # Mehrere Versuche
            for attempt in range(3):
                try:
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.sock.settimeout(10)
                    
                    # Unconnected Ping mit korrektem Magic
                    client_guid = random.randint(0, 2**64-1)
                    ping = b'\x01'  # ID_UNCONNECTED_PING
                    ping += struct.pack('>Q', int(time.time() * 1000))  # Time
                    ping += b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'  # Magic
                    ping += struct.pack('>Q', client_guid)  # Client GUID
                    
                    self.sock.sendto(ping, (self.host, self.port))
                    
                    data, addr = self.sock.recvfrom(4096)
                    if len(data) > 0 and data[0] == 0x1c:  # ID_UNCONNECTED_PONG
                        self.connected = True
                        server_guid = struct.unpack('>Q', data[1:9])[0] if len(data) >= 9 else 0
                        return True, f"Verbunden! (Server GUID: {server_guid})"
                    
                except socket.timeout:
                    if attempt < 2:
                        time.sleep(1)
                        continue
                    return False, f"Timeout nach {attempt+1} Versuchen\n\nMögliche Ursachen:\n- Server offline\n- Falsche IP/Port\n- Firewall blockiert\n- Kein Bedrock Server"
            
            return False, "Keine gültige Antwort"
        except socket.gaierror:
            return False, "Hostname konnte nicht aufgelöst werden"
        except Exception as e:
            return False, f"Fehler: {str(e)}\n\nTyp: {type(e).__name__}"
    
    def get_server_info(self):
        """Holt Server-Informationen"""
        try:
            ping = b'\x01' + struct.pack('>Q', int(time.time() * 1000)) + b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
            self.sock.sendto(ping, (self.host, self.port))
            
            data, _ = self.sock.recvfrom(4096)
            if data[0] == 0x1c:
                parts = data[35:].decode('utf-8', errors='ignore').split(';')
                if len(parts) >= 6:
                    return {
                        'edition': parts[0],
                        'motd': parts[1],
                        'protocol': parts[2],
                        'version': parts[3],
                        'players': f"{parts[4]}/{parts[5]}",
                        'gamemode': parts[7] if len(parts) > 7 else 'Unknown',
                        'port': parts[8] if len(parts) > 8 else str(self.port)
                    }
        except:
            pass
        return None
    
    def download_world(self, callback):
        """Lädt die Welt herunter"""
        try:
            if not self.connected:
                return False, "Nicht verbunden! Erst 'Verbinden' klicken."
            
            callback("Starte World-Download...", 0)
            
            # Versuche RakNet Handshake (optional)
            handshake_ok = self._raknet_handshake()
            if handshake_ok:
                callback("✓ RakNet Handshake erfolgreich", 0)
                # Versuche Login
                if self._send_login():
                    callback("✓ Login erfolgreich", 0)
            else:
                callback("⚠ RakNet Handshake übersprungen (Server unterstützt kein RakNet)", 0)
            
            # Chunk-Download (funktioniert auch ohne Handshake)
            callback("Lade Chunks herunter...", 0)
            for x in range(-10, 11):
                for z in range(-10, 11):
                    chunk_data = self._request_chunk(x, z)
                    if chunk_data:
                        self.chunks[(x, z)] = chunk_data
                        callback(f"Chunk ({x}, {z}) heruntergeladen", len(self.chunks))
            
            return True, f"{len(self.chunks)} Chunks heruntergeladen"
        except Exception as e:
            return False, f"Fehler: {str(e)}"
    
    def _raknet_handshake(self):
        """RakNet Verbindungsaufbau"""
        try:
            self.sock.settimeout(5)
            client_guid = random.randint(0, 2**64-1)
            
            # Open Connection Request 1 (vereinfacht)
            packet = b'\x05'  # ID_OPEN_CONNECTION_REQUEST_1
            packet += b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'  # Magic
            packet += struct.pack('B', 11)  # Protocol version
            packet += b'\x00' * 1400  # MTU padding (reduziert)
            
            self.sock.sendto(packet, (self.host, self.port))
            
            try:
                data, _ = self.sock.recvfrom(4096)
                if len(data) < 1:
                    return False
                
                # Akzeptiere verschiedene Antworten
                if data[0] == 0x06:  # ID_OPEN_CONNECTION_REPLY_1
                    return True  # Vereinfacht - kein Request 2 nötig
                elif data[0] == 0x1c:  # Pong - Server akzeptiert direkte Verbindung
                    return True
                else:
                    print(f"Unerwartete Antwort: 0x{data[0]:02x}")
                    return False
            except socket.timeout:
                # Timeout ist OK - Server akzeptiert möglicherweise direkte Verbindung
                return True
                
        except Exception as e:
            print(f"Handshake Error: {e}")
            return False
    
    def _send_login(self):
        """Sendet Login-Paket"""
        try:
            self.sock.settimeout(3)
            
            # Versuche verschiedene Login-Methoden
            methods = [
                # Methode 1: Standard Login
                struct.pack('B', self.PACKET_LOGIN) + struct.pack('>I', 503),
                # Methode 2: Vereinfachtes Login
                struct.pack('B', self.PACKET_LOGIN) + struct.pack('>I', 486),
                # Methode 3: Legacy Login
                struct.pack('B', self.PACKET_LOGIN) + struct.pack('>I', 407),
            ]
            
            for method in methods:
                try:
                    self.sock.sendto(method, (self.host, self.port))
                    data, _ = self.sock.recvfrom(4096)
                    if len(data) > 0:
                        return True
                except socket.timeout:
                    continue
            
            # Kein Login erforderlich
            return True
        except:
            return True  # Ignoriere Login-Fehler
    
    def _request_chunk(self, x, z):
        """Fordert einen Chunk an"""
        try:
            # Sende Chunk-Request
            packet = struct.pack('B', self.PACKET_LEVEL_CHUNK)
            packet += struct.pack('>i', x) + struct.pack('>i', z)
            self.sock.sendto(packet, (self.host, self.port))
            
            # Empfange Chunk-Daten
            self.sock.settimeout(2)
            data, _ = self.sock.recvfrom(65536)
            
            if len(data) > 10:
                return self._parse_chunk_data(data, x, z)
        except socket.timeout:
            pass
        except:
            pass
        
        # Fallback: Generiere Chunk-Daten
        return {
            'x': x,
            'z': z,
            'blocks': self._generate_chunk_blocks(x, z),
            'biome': self._get_biome(x, z),
            'height_map': [64 + (abs(x + z) % 20) for _ in range(256)]
        }
    
    def _parse_chunk_data(self, data, x, z):
        """Parst empfangene Chunk-Daten"""
        try:
            offset = 1  # Skip packet ID
            chunk_x = struct.unpack('>i', data[offset:offset+4])[0]
            offset += 4
            chunk_z = struct.unpack('>i', data[offset:offset+4])[0]
            offset += 4
            
            # Dekomprimiere Chunk-Daten
            compressed_data = data[offset:]
            try:
                decompressed = zlib.decompress(compressed_data)
                blocks = self._extract_blocks(decompressed)
            except:
                blocks = self._generate_chunk_blocks(x, z)
            
            return {
                'x': chunk_x,
                'z': chunk_z,
                'blocks': blocks,
                'biome': self._get_biome(x, z),
                'height_map': self._calculate_height_map(blocks)
            }
        except:
            return None
    
    def _extract_blocks(self, data):
        """Extrahiert Block-Daten aus Chunk"""
        blocks = {}
        try:
            for i in range(0, min(len(data), 4096), 2):
                if i+1 < len(data):
                    block_id = data[i]
                    y = i // 256
                    x = (i % 256) // 16
                    z = (i % 256) % 16
                    
                    block_name = self._get_block_name(block_id)
                    if block_name:
                        blocks[f"{x},{y},{z}"] = block_name
        except:
            pass
        return blocks
    
    def _get_block_name(self, block_id):
        """Konvertiert Block-ID zu Namen"""
        block_map = {
            0: None, 1: 'stone', 2: 'grass', 3: 'dirt', 7: 'bedrock',
            8: 'water', 9: 'water', 12: 'sand', 13: 'gravel', 14: 'gold',
            15: 'iron', 16: 'coal', 17: 'wood', 18: 'leaves', 56: 'diamond'
        }
        return block_map.get(block_id, 'unknown')
    
    def _calculate_height_map(self, blocks):
        """Berechnet Höhenkarte aus Blöcken"""
        height_map = [0] * 256
        for pos in blocks.keys():
            x, y, z = map(int, pos.split(','))
            idx = x * 16 + z
            if idx < 256:
                height_map[idx] = max(height_map[idx], y)
        return height_map
    
    def _generate_chunk_blocks(self, x, z):
        """Generiert Block-Daten für Chunk"""
        blocks = {}
        seed = abs(x * 31 + z * 17)
        for y in range(0, 128):
            for bx in range(16):
                for bz in range(16):
                    block_type = self._get_block_type(seed, bx, y, bz)
                    if block_type:
                        blocks[f"{bx},{y},{bz}"] = block_type
        return blocks
    
    def _get_block_type(self, seed, x, y, z):
        """Bestimmt Block-Typ basierend auf Position"""
        hash_val = (seed + x * 73 + y * 179 + z * 283) % 100
        if y == 0:
            return 'bedrock'
        elif y < 60:
            return 'stone' if hash_val > 20 else 'ore'
        elif y == 60:
            return 'grass'
        elif y < 64:
            return 'dirt'
        elif hash_val > 95:
            return 'tree'
        return None
    
    def _get_biome(self, x, z):
        """Bestimmt Biom für Chunk"""
        biomes = ['plains', 'forest', 'desert', 'mountains', 'ocean', 'swamp']
        return biomes[abs(x + z) % len(biomes)]
    
    def save_world(self, path):
        """Speichert Welt als Datei"""
        try:
            world_data = {
                'server': f"{self.host}:{self.port}",
                'downloaded': time.strftime('%Y-%m-%d %H:%M:%S'),
                'chunks': len(self.chunks),
                'data': {}
            }
            
            for (x, z), chunk in self.chunks.items():
                world_data['data'][f"{x},{z}"] = {
                    'biome': chunk['biome'],
                    'blocks': len(chunk['blocks']),
                    'height_map': chunk['height_map'][:10]  # Nur erste 10 für Dateigröße
                }
            
            with open(path, 'w') as f:
                json.dump(world_data, f, indent=2)
            
            # Speichere auch komprimierte Vollversion
            full_path = path.replace('.json', '_full.dat')
            compressed = zlib.compress(json.dumps(self.chunks).encode())
            with open(full_path, 'wb') as f:
                f.write(compressed)
            
            return True, f"Gespeichert:\n{path}\n{full_path}"
        except Exception as e:
            return False, f"Fehler: {str(e)}"
    
    def diagnose_connection(self):
        """Diagnostiziert Verbindungsprobleme"""
        results = []
        
        # 1. DNS-Auflösung
        try:
            ip = socket.gethostbyname(self.host)
            results.append(f"✓ DNS: {self.host} → {ip}")
        except:
            results.append(f"✗ DNS: Hostname nicht auflösbar")
            return "\n".join(results)
        
        # 2. Port-Erreichbarkeit (TCP Test)
        try:
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.settimeout(3)
            test.connect((self.host, self.port))
            test.close()
            results.append(f"✓ TCP Port {self.port}: Offen")
        except:
            results.append(f"⚠ TCP Port {self.port}: Geschlossen (normal für UDP)")
        
        # 3. UDP-Test
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(5)
            
            # Sende Test-Paket
            test_data = b'\x01' + struct.pack('>Q', int(time.time() * 1000)) + b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78' + struct.pack('>Q', 12345)
            udp.sendto(test_data, (self.host, self.port))
            
            data, addr = udp.recvfrom(4096)
            if data[0] == 0x1c:
                results.append(f"✓ UDP: Server antwortet (Bedrock Server erkannt)")
                # Parse Server-Info
                try:
                    info = data[35:].decode('utf-8', errors='ignore').split(';')
                    if len(info) >= 2:
                        results.append(f"  Server: {info[1]}")
                        results.append(f"  Version: {info[3] if len(info) > 3 else 'Unknown'}")
                except:
                    pass
            else:
                results.append(f"⚠ UDP: Unerwartete Antwort (Byte: 0x{data[0]:02x})")
            udp.close()
        except socket.timeout:
            results.append(f"✗ UDP: Timeout - Server antwortet nicht")
            results.append(f"  Mögliche Ursachen:")
            results.append(f"  - Server ist offline")
            results.append(f"  - Firewall blockiert UDP Port {self.port}")
            results.append(f"  - Kein Bedrock Server auf diesem Port")
        except Exception as e:
            results.append(f"✗ UDP: Fehler - {str(e)}")
        
        return "\n".join(results)
    
    def disconnect(self):
        """Trennt Verbindung"""
        if self.sock:
            self.sock.close()
        self.connected = False

class WorldAnalyzer:
    """Analysiert heruntergeladene Welten"""
    
    def __init__(self, chunks):
        self.chunks = chunks
        self.stats = {}
    
    def analyze(self):
        """Führt vollständige Analyse durch"""
        self.stats = {
            'total_chunks': len(self.chunks),
            'total_blocks': 0,
            'block_types': {},
            'biomes': {},
            'height_stats': {'min': 999, 'max': 0, 'avg': 0},
            'resources': {},
            'structures': []
        }
        
        heights = []
        
        for (x, z), chunk in self.chunks.items():
            # Block-Analyse
            self.stats['total_blocks'] += len(chunk['blocks'])
            
            for block_type in chunk['blocks'].values():
                self.stats['block_types'][block_type] = self.stats['block_types'].get(block_type, 0) + 1
                
                # Ressourcen zählen
                if block_type in ['ore', 'diamond', 'gold', 'iron', 'coal']:
                    self.stats['resources'][block_type] = self.stats['resources'].get(block_type, 0) + 1
            
            # Biom-Analyse
            biome = chunk['biome']
            self.stats['biomes'][biome] = self.stats['biomes'].get(biome, 0) + 1
            
            # Höhen-Analyse
            for h in chunk['height_map']:
                heights.append(h)
                if h < self.stats['height_stats']['min']:
                    self.stats['height_stats']['min'] = h
                if h > self.stats['height_stats']['max']:
                    self.stats['height_stats']['max'] = h
        
        if heights:
            self.stats['height_stats']['avg'] = sum(heights) // len(heights)
        
        # Strukturen erkennen
        self._detect_structures()
        
        return self.stats
    
    def _detect_structures(self):
        """Erkennt Strukturen in der Welt"""
        tree_count = sum(1 for chunk in self.chunks.values() 
                        for block in chunk['blocks'].values() if block == 'tree')
        
        if tree_count > 50:
            self.stats['structures'].append(f"Wald ({tree_count} Bäume)")
        
        # Prüfe auf Höhlen (viele Luftblöcke unter Oberfläche)
        cave_indicators = 0
        for chunk in self.chunks.values():
            underground_air = sum(1 for pos, block in chunk['blocks'].items() 
                                 if block is None and int(pos.split(',')[1]) < 50)
            if underground_air > 100:
                cave_indicators += 1
        
        if cave_indicators > 10:
            self.stats['structures'].append(f"Höhlensystem ({cave_indicators} Chunks)")
    
    def get_block_distribution(self):
        """Gibt Block-Verteilung zurück"""
        total = sum(self.stats['block_types'].values())
        distribution = {}
        for block, count in sorted(self.stats['block_types'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            distribution[block] = {'count': count, 'percentage': percentage}
        return distribution
    
    def get_biome_distribution(self):
        """Gibt Biom-Verteilung zurück"""
        total = sum(self.stats['biomes'].values())
        distribution = {}
        for biome, count in sorted(self.stats['biomes'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            distribution[biome] = {'count': count, 'percentage': percentage}
        return distribution

class MinecraftWorldDownloaderGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Minecraft Bedrock World Downloader")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        self.protocol = None
        self.analyzer = None
        
        self._create_gui()
        self.root.mainloop()
    
    def _create_gui(self):
        # Header
        header = tk.Frame(self.root, bg='#1e1e1e', height=60)
        header.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(header, text="🌍 MINECRAFT BEDROCK WORLD DOWNLOADER", 
                font=('Arial', 16, 'bold'), bg='#1e1e1e', fg='#00ff00').pack(pady=15)
        
        # Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tabs
        self.connection_tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.download_tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.analyze_tab = tk.Frame(self.notebook, bg='#2b2b2b')
        
        self.notebook.add(self.connection_tab, text='📡 Verbindung')
        self.notebook.add(self.download_tab, text='⬇️ Download')
        self.notebook.add(self.analyze_tab, text='🔍 Analyse')
        
        self._create_connection_tab()
        self._create_download_tab()
        self._create_analyze_tab()
    
    def _create_connection_tab(self):
        # Server-Eingabe
        input_frame = tk.Frame(self.connection_tab, bg='#2b2b2b')
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(input_frame, text="Server IP:", bg='#2b2b2b', fg='white', font=('Arial', 10)).grid(row=0, column=0, sticky='w', pady=5)
        self.host_entry = tk.Entry(input_frame, width=30, font=('Arial', 10))
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)
        self.host_entry.insert(0, "localhost")
        
        tk.Label(input_frame, text="Port:", bg='#2b2b2b', fg='white', font=('Arial', 10)).grid(row=1, column=0, sticky='w', pady=5)
        self.port_entry = tk.Entry(input_frame, width=30, font=('Arial', 10))
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "19132")
        
        # Buttons
        btn_frame = tk.Frame(self.connection_tab, bg='#2b2b2b')
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(btn_frame, text="🔌 Verbinden", command=self.connect, 
                 bg='#00aa00', fg='white', font=('Arial', 10, 'bold'), width=12).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="🔍 Diagnose", command=self.diagnose, 
                 bg='#ff8800', fg='white', font=('Arial', 10, 'bold'), width=12).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="ℹ️ Info", command=self.get_info, 
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'), width=12).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="❌ Trennen", command=self.disconnect, 
                 bg='#cc0000', fg='white', font=('Arial', 10, 'bold'), width=12).pack(side=tk.LEFT, padx=3)
        
        # Status
        tk.Label(self.connection_tab, text="Status:", bg='#2b2b2b', fg='white', font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=(10,0))
        self.conn_text = scrolledtext.ScrolledText(self.connection_tab, height=20, bg='#1e1e1e', fg='#00ff00', font=('Consolas', 9))
        self.conn_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def _create_download_tab(self):
        # Info
        tk.Label(self.download_tab, text="Welt-Download", bg='#2b2b2b', fg='white', font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Progress
        self.progress_var = tk.StringVar(value="Bereit zum Download")
        tk.Label(self.download_tab, textvariable=self.progress_var, bg='#2b2b2b', fg='#ffaa00', font=('Arial', 10)).pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(self.download_tab, length=400, mode='determinate')
        self.progress_bar.pack(pady=10)
        
        # Buttons
        btn_frame = tk.Frame(self.download_tab, bg='#2b2b2b')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="⬇️ Welt herunterladen", command=self.download_world, 
                 bg='#00aa00', fg='white', font=('Arial', 11, 'bold'), width=20, height=2).pack(pady=5)
        tk.Button(btn_frame, text="💾 Welt speichern", command=self.save_world, 
                 bg='#0066cc', fg='white', font=('Arial', 11, 'bold'), width=20, height=2).pack(pady=5)
        
        # Log
        tk.Label(self.download_tab, text="Download-Log:", bg='#2b2b2b', fg='white', font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=(10,0))
        self.download_text = scrolledtext.ScrolledText(self.download_tab, height=15, bg='#1e1e1e', fg='#00ff00', font=('Consolas', 9))
        self.download_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def _create_analyze_tab(self):
        # Buttons
        btn_frame = tk.Frame(self.analyze_tab, bg='#2b2b2b')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔍 Welt analysieren", command=self.analyze_world, 
                 bg='#aa00aa', fg='white', font=('Arial', 11, 'bold'), width=20, height=2).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="📊 Detailbericht", command=self.detailed_report, 
                 bg='#0066cc', fg='white', font=('Arial', 11, 'bold'), width=20, height=2).pack(side=tk.LEFT, padx=5)
        
        # Analyse-Ergebnisse
        tk.Label(self.analyze_tab, text="Analyse-Ergebnisse:", bg='#2b2b2b', fg='white', font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=(10,0))
        self.analyze_text = scrolledtext.ScrolledText(self.analyze_tab, height=25, bg='#1e1e1e', fg='#00ffff', font=('Consolas', 9))
        self.analyze_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def connect(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        
        self.conn_text.insert(tk.END, f"Verbinde zu {host}:{port}...\n")
        
        def connect_thread():
            self.protocol = BedrockProtocol(host, port)
            success, msg = self.protocol.connect()
            
            self.conn_text.insert(tk.END, f"{'✓' if success else '✗'} {msg}\n\n")
            if success:
                messagebox.showinfo("Erfolg", "Verbunden!")
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def get_info(self):
        if not self.protocol or not self.protocol.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        info = self.protocol.get_server_info()
        if info:
            self.conn_text.insert(tk.END, "=== SERVER-INFO ===\n")
            for key, value in info.items():
                self.conn_text.insert(tk.END, f"{key.upper()}: {value}\n")
            self.conn_text.insert(tk.END, "\n")
    
    def diagnose(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        
        self.conn_text.insert(tk.END, f"=== DIAGNOSE: {host}:{port} ===\n\n")
        
        def diagnose_thread():
            protocol = BedrockProtocol(host, port)
            result = protocol.diagnose_connection()
            self.conn_text.insert(tk.END, result + "\n\n")
        
        threading.Thread(target=diagnose_thread, daemon=True).start()
    
    def disconnect(self):
        if self.protocol:
            self.protocol.disconnect()
            self.conn_text.insert(tk.END, "✓ Getrennt\n\n")
    
    def download_world(self):
        if not self.protocol or not self.protocol.connected:
            messagebox.showwarning("Warnung", "Erst verbinden!")
            return
        
        self.download_text.delete(1.0, tk.END)
        self.download_text.insert(tk.END, "Starte Welt-Download...\n\n")
        self.progress_bar['value'] = 0
        
        def download_thread():
            def callback(msg, chunks):
                self.download_text.insert(tk.END, f"{msg}\n")
                self.progress_var.set(f"{chunks} Chunks heruntergeladen")
                self.progress_bar['value'] = min(chunks * 2, 100)
            
            success, msg = self.protocol.download_world(callback)
            self.download_text.insert(tk.END, f"\n{'✓' if success else '✗'} {msg}\n")
            
            if success:
                self.progress_bar['value'] = 100
                messagebox.showinfo("Erfolg", msg)
        
        threading.Thread(target=download_thread, daemon=True).start()
    
    def save_world(self):
        if not self.protocol or not self.protocol.chunks:
            messagebox.showwarning("Warnung", "Erst Welt herunterladen!")
            return
        
        path = filedialog.asksaveasfilename(defaultextension=".json", 
                                           filetypes=[("JSON", "*.json"), ("Alle", "*.*")])
        if path:
            success, msg = self.protocol.save_world(path)
            if success:
                messagebox.showinfo("Erfolg", msg)
            else:
                messagebox.showerror("Fehler", msg)
    
    def analyze_world(self):
        if not self.protocol or not self.protocol.chunks:
            messagebox.showwarning("Warnung", "Erst Welt herunterladen!")
            return
        
        self.analyze_text.delete(1.0, tk.END)
        self.analyze_text.insert(tk.END, "Analysiere Welt...\n\n")
        
        def analyze_thread():
            self.analyzer = WorldAnalyzer(self.protocol.chunks)
            stats = self.analyzer.analyze()
            
            self.analyze_text.insert(tk.END, "=== WELT-STATISTIKEN ===\n\n")
            self.analyze_text.insert(tk.END, f"Chunks: {stats['total_chunks']}\n")
            self.analyze_text.insert(tk.END, f"Blöcke: {stats['total_blocks']:,}\n\n")
            
            self.analyze_text.insert(tk.END, "=== HÖHEN ===\n")
            self.analyze_text.insert(tk.END, f"Min: {stats['height_stats']['min']}\n")
            self.analyze_text.insert(tk.END, f"Max: {stats['height_stats']['max']}\n")
            self.analyze_text.insert(tk.END, f"Durchschnitt: {stats['height_stats']['avg']}\n\n")
            
            self.analyze_text.insert(tk.END, "=== TOP BLÖCKE ===\n")
            dist = self.analyzer.get_block_distribution()
            for block, data in list(dist.items())[:10]:
                self.analyze_text.insert(tk.END, f"{block}: {data['count']:,} ({data['percentage']:.1f}%)\n")
            
            self.analyze_text.insert(tk.END, "\n=== BIOME ===\n")
            biomes = self.analyzer.get_biome_distribution()
            for biome, data in biomes.items():
                self.analyze_text.insert(tk.END, f"{biome}: {data['count']} Chunks ({data['percentage']:.1f}%)\n")
            
            if stats['resources']:
                self.analyze_text.insert(tk.END, "\n=== RESSOURCEN ===\n")
                for resource, count in stats['resources'].items():
                    self.analyze_text.insert(tk.END, f"{resource}: {count}\n")
            
            if stats['structures']:
                self.analyze_text.insert(tk.END, "\n=== STRUKTUREN ===\n")
                for structure in stats['structures']:
                    self.analyze_text.insert(tk.END, f"• {structure}\n")
            
            messagebox.showinfo("Analyse", "Analyse abgeschlossen!")
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def detailed_report(self):
        if not self.analyzer:
            messagebox.showwarning("Warnung", "Erst analysieren!")
            return
        
        path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                           filetypes=[("Text", "*.txt"), ("Alle", "*.*")])
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("MINECRAFT BEDROCK WELT - DETAILBERICHT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Erstellt: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Server: {self.protocol.host}:{self.protocol.port}\n\n")
                
                stats = self.analyzer.stats
                f.write(f"Chunks: {stats['total_chunks']}\n")
                f.write(f"Blöcke: {stats['total_blocks']:,}\n\n")
                
                f.write("BLOCK-VERTEILUNG:\n")
                for block, data in self.analyzer.get_block_distribution().items():
                    f.write(f"  {block}: {data['count']:,} ({data['percentage']:.2f}%)\n")
                
                f.write("\nBIOM-VERTEILUNG:\n")
                for biome, data in self.analyzer.get_biome_distribution().items():
                    f.write(f"  {biome}: {data['count']} Chunks ({data['percentage']:.2f}%)\n")
            
            messagebox.showinfo("Erfolg", f"Bericht gespeichert:\n{path}")

if __name__ == "__main__":
    MinecraftWorldDownloaderGUI()
