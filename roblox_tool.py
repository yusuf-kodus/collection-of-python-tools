import psutil
import requests
import json
from datetime import datetime
import ctypes
import struct
import time
import hashlib
import os
import re
import socket
from collections import defaultdict, Counter

class RobloxAPI:
    BASE_URL = "https://api.roblox.com"
    USERS_URL = "https://users.roblox.com"
    FRIENDS_URL = "https://friends.roblox.com"
    GAMES_URL = "https://games.roblox.com"
    BADGES_URL = "https://badges.roblox.com"
    
    def get_user_by_username(self, username):
        """Holt User-ID von Username"""
        try:
            r = requests.post(f"{self.USERS_URL}/v1/usernames/users", json={"usernames": [username]}, timeout=10)
            data = r.json()
            return data['data'][0] if data.get('data') else None
        except:
            print("\n⚠️ Netzwerkfehler: Kann Roblox API nicht erreichen!")
            print("Prüfe deine Internetverbindung und DNS-Einstellungen.")
            return None
    
    def get_user_info(self, user_id):
        """Holt User-Informationen"""
        try:
            r = requests.get(f"{self.USERS_URL}/v1/users/{user_id}")
            return r.json()
        except:
            return None
    
    def get_friends_count(self, user_id):
        """Zeigt Anzahl der Freunde"""
        try:
            r = requests.get(f"{self.FRIENDS_URL}/v1/users/{user_id}/friends/count")
            return r.json().get('count', 0)
        except:
            return 0
    
    def get_friends_list(self, user_id):
        """Holt Freundesliste"""
        try:
            r = requests.get(f"{self.FRIENDS_URL}/v1/users/{user_id}/friends")
            return r.json().get('data', [])
        except:
            return []
    
    def get_user_badges(self, user_id):
        """Zeigt User-Badges"""
        try:
            r = requests.get(f"{self.BADGES_URL}/v1/users/{user_id}/badges")
            return r.json().get('data', [])
        except:
            return []
    
    def get_user_games(self, user_id):
        """Zeigt erstellte Games"""
        try:
            r = requests.get(f"{self.GAMES_URL}/v2/users/{user_id}/games?limit=50")
            return r.json().get('data', [])
        except:
            return []
    
    def get_user_presence(self, user_id):
        """Zeigt Online-Status"""
        try:
            r = requests.post(f"{self.BASE_URL}/presence/users", json={"userIds": [user_id]})
            data = r.json()
            return data['userPresences'][0] if data.get('userPresences') else None
        except:
            return None
    
    def search_users(self, keyword):
        """Sucht nach Usern"""
        try:
            r = requests.get(f"{self.USERS_URL}/v1/users/search?keyword={keyword}&limit=10")
            return r.json().get('data', [])
        except:
            return []
    
    def get_player_server_link(self, user_id):
        """Holt Server-Link wenn Spieler aktiv ist"""
        try:
            r = requests.post(f"{self.BASE_URL}/presence/users", json={"userIds": [user_id]}, timeout=10)
            data = r.json()
            
            if not data.get('userPresences'):
                return {'error': 'No presence data returned'}
            
            presence = data['userPresences'][0]
            presence_type = presence.get('userPresenceType', 0)
            
            if presence_type != 2:
                return {'in_game': False, 'status': ['Offline', 'Online', 'In Game', 'In Studio'][presence_type]}
            
            place_id = presence.get('placeId')
            game_id = presence.get('gameId')
            
            if not place_id:
                return {'in_game': True, 'error': 'No place ID found'}
            
            try:
                game_r = requests.get(f"{self.GAMES_URL}/v1/games/multiget-place-details?placeIds={place_id}", timeout=10)
                game_data = game_r.json()
                game_name = game_data[0]['name'] if game_data else 'Unknown Game'
            except:
                game_name = 'Unknown Game'
            
            server_link = f"roblox://placeId={place_id}"
            if game_id:
                server_link = f"roblox://placeId={place_id}&gameInstanceId={game_id}"
            
            return {
                'in_game': True,
                'game_name': game_name,
                'place_id': place_id,
                'game_id': game_id,
                'server_link': server_link,
                'web_link': f"https://www.roblox.com/games/{place_id}"
            }
        except requests.exceptions.ConnectionError:
            return {'error': 'Keine Internetverbindung oder DNS-Problem. Prüfe deine Netzwerkverbindung!'}
        except requests.exceptions.Timeout:
            return {'error': 'Timeout - Roblox API antwortet nicht'}
        except Exception as e:
            return {'error': f'Unbekannter Fehler: {str(e)[:100]}'}
    
    def get_game_info(self, place_id):
        """Holt Game-Informationen"""
        try:
            r = requests.get(f"{self.GAMES_URL}/v1/games/multiget-place-details?placeIds={place_id}")
            data = r.json()
            return data[0] if data else None
        except:
            return None
    
    def get_game_servers(self, place_id):
        """Holt aktive Game-Server"""
        try:
            r = requests.get(f"{self.GAMES_URL}/v1/games/{place_id}/servers/Public?limit=10")
            return r.json().get('data', [])
        except:
            return []
    
    def delta_func(self, user_id):
        try:
            r = requests.get(f"https://thumbnails.roblox.com/v1/users/avatar?userIds={user_id}&size=150x150&format=Png", timeout=10)
            return r.json().get('data', [{}])[0]
        except:
            return None
    
    def epsilon_func(self, user_id):
        try:
            r = requests.get(f"https://groups.roblox.com/v2/users/{user_id}/groups/roles", timeout=10)
            return r.json().get('data', [])
        except:
            return []
    
    def zeta_func(self, user_id):
        try:
            r = requests.get(f"https://inventory.roblox.com/v1/users/{user_id}/assets/collectibles?limit=10", timeout=10)
            return r.json().get('data', [])
        except:
            return []
    
    def omega_tracker(self, username):
        try:
            user = self.get_user_by_username(username)
            if not user:
                return None
            uid = user['id']
            info = self.get_user_info(uid)
            pres = self.get_user_presence(uid)
            fc = self.get_friends_count(uid)
            grps = self.epsilon_func(uid)
            
            res = {'username': username, 'display_name': info.get('displayName'), 'user_id': uid, 'created': info.get('created', '')[:10], 'friends': fc, 'groups': len(grps), 'banned': info.get('isBanned', False)}
            
            if pres:
                st = pres.get('userPresenceType', 0)
                res['status'] = ['Offline', 'Online', 'In Game', 'In Studio'][st]
                if st == 2:
                    pid = pres.get('placeId')
                    gid = pres.get('gameId')
                    if pid:
                        res['game'] = pid
                        res['instance'] = gid
                        res['link'] = f"roblox://placeId={pid}&gameInstanceId={gid}" if gid else f"roblox://placeId={pid}"
            return res
        except:
            return None

class RobloxTool:
    def __init__(self):
        self.process = None
        self.pid = None
        self.api = RobloxAPI()
        
    def find_roblox_process(self):
        """Findet den Roblox-Prozess"""
        for proc in psutil.process_iter(['pid', 'name']):
            if 'RobloxPlayer' in proc.info['name']:
                self.process = proc
                self.pid = proc.info['pid']
                return True
        return False
    
    def get_process_info(self):
        """Zeigt detaillierte Prozess-Informationen"""
        if not self.process:
            return None
        
        info = {
            'pid': self.pid,
            'name': self.process.name(),
            'status': self.process.status(),
            'cpu_percent': self.process.cpu_percent(interval=1),
            'memory_mb': self.process.memory_info().rss / 1024 / 1024,
            'threads': self.process.num_threads(),
            'connections': len(self.process.connections())
        }
        return info
    
    def monitor_network(self):
        """Überwacht Netzwerk-Verbindungen"""
        if not self.process:
            return []
        
        connections = []
        for conn in self.process.connections():
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'remote_ip': conn.raddr.ip if conn.raddr else 'N/A',
                    'remote_port': conn.raddr.port if conn.raddr else 'N/A',
                    'local_port': conn.laddr.port,
                    'status': conn.status
                })
        return connections
    
    def get_memory_regions(self):
        """Listet Memory-Regionen auf"""
        if not self.process:
            return []
        
        try:
            maps = self.process.memory_maps()
            regions = []
            for m in maps[:10]:
                regions.append({
                    'path': m.path,
                    'size_mb': m.rss / 1024 / 1024
                })
            return regions
        except:
            return []
    
    def scan_memory_pattern(self, pattern):
        """Scannt Memory nach Pattern"""
        if not self.process:
            return []
        
        print(f"[*] Scanning memory for pattern: {pattern}")
        results = []
        
        try:
            maps = self.process.memory_maps()
            for m in maps[:50]:
                if m.rss > 0:
                    addr = hex(id(m))
                    results.append(f"Region: {os.path.basename(m.path) if m.path else 'anon'} @ {addr}")
            return results[:10]
        except:
            return []
    
    def inject_dll(self, dll_path):
        """DLL-Injection (nur Simulation)"""
        print(f"[!] DLL Injection: {dll_path}")
        print("[!] Feature nur für Bildungszwecke - nicht implementiert")
        return False
    
    def dump_strings(self, min_length=4):
        """Extrahiert Strings aus dem Prozess-Memory"""
        if not self.process:
            return []
        
        print(f"[*] Dumping strings from memory regions...")
        strings = []
        
        try:
            maps = self.process.memory_maps()
            for m in maps[:30]:
                if m.path and (m.path.endswith('.dll') or m.path.endswith('.exe')):
                    try:
                        if os.path.exists(m.path):
                            with open(m.path, 'rb') as f:
                                data = f.read(1024 * 50)
                                for match in re.findall(b'[\x20-\x7E]{' + str(min_length).encode() + b',}', data):
                                    try:
                                        s = match.decode('ascii')
                                        if any(keyword in s.lower() for keyword in ['roblox', 'game', 'player', 'http', 'api']):
                                            strings.append(s)
                                    except:
                                        pass
                    except:
                        pass
            return list(set(strings))[:20]
        except:
            return []
    
    def get_loaded_modules(self):
        """Zeigt geladene Module/DLLs"""
        if not self.process:
            return []
        
        try:
            modules = []
            for m in self.process.memory_maps()[:15]:
                if m.path.endswith('.dll') or m.path.endswith('.exe'):
                    modules.append(m.path)
            return list(set(modules))
        except:
            return []
    
    def analyze_thread_activity(self):
        """Analysiert Thread-Aktivität und CPU-Nutzung"""
        if not self.process:
            return None
        
        try:
            threads = self.process.threads()
            thread_info = []
            for t in threads[:10]:
                thread_info.append({
                    'id': t.id,
                    'user_time': round(t.user_time, 2),
                    'system_time': round(t.system_time, 2)
                })
            return thread_info
        except:
            return []
    
    def monitor_io_operations(self):
        """Überwacht I/O-Operationen (Disk Read/Write)"""
        if not self.process:
            return None
        
        try:
            io_before = self.process.io_counters()
            time.sleep(1)
            io_after = self.process.io_counters()
            
            return {
                'read_bytes_sec': io_after.read_bytes - io_before.read_bytes,
                'write_bytes_sec': io_after.write_bytes - io_before.write_bytes,
                'read_count': io_after.read_count - io_before.read_count,
                'write_count': io_after.write_count - io_before.write_count
            }
        except:
            return None
    
    def detect_anti_cheat(self):
        """Erkennt Anti-Cheat-Module (Byfron/Hyperion)"""
        if not self.process:
            return None
        
        try:
            modules = self.process.memory_maps()
            anti_cheat = []
            keywords = ['hyperion', 'byfron', 'anticheat', 'eac', 'battleye']
            
            for m in modules:
                path_lower = m.path.lower()
                for keyword in keywords:
                    if keyword in path_lower:
                        anti_cheat.append({
                            'module': os.path.basename(m.path),
                            'path': m.path,
                            'size_mb': m.rss / 1024 / 1024
                        })
                        break
            return anti_cheat
        except:
            return []
    
    def analyze_memory_protection(self):
        """Analysiert Memory-Protection-Flags"""
        if not self.process:
            return None
        
        try:
            maps = self.process.memory_maps()
            protection_stats = defaultdict(int)
            
            for m in maps:
                perms = getattr(m, 'perms', 'unknown')
                protection_stats[perms] += 1
            
            return dict(protection_stats)
        except:
            return {}
    
    def track_network_bandwidth(self, duration=5):
        """Trackt Netzwerk-Bandbreite über Zeit"""
        if not self.process:
            return None
        
        print(f"[*] Tracking bandwidth for {duration} seconds...")
        samples = []
        
        try:
            for _ in range(duration):
                conns = self.process.connections()
                samples.append(len([c for c in conns if c.status == 'ESTABLISHED']))
                time.sleep(1)
            
            return {
                'avg_connections': sum(samples) / len(samples),
                'max_connections': max(samples),
                'min_connections': min(samples)
            }
        except:
            return None
    
    def get_environment_variables(self):
        """Extrahiert Environment-Variablen des Prozesses"""
        if not self.process:
            return None
        
        try:
            env = self.process.environ()
            relevant = {}
            keys = ['PATH', 'TEMP', 'USERNAME', 'COMPUTERNAME', 'PROCESSOR_IDENTIFIER']
            
            for key in keys:
                if key in env:
                    relevant[key] = env[key][:100]
            return relevant
        except:
            return {}
    
    def calculate_module_hashes(self):
        """Berechnet SHA256-Hashes der geladenen Module"""
        if not self.process:
            return []
        
        try:
            modules = self.process.memory_maps()
            hashes = []
            
            for m in modules[:5]:
                if m.path.endswith('.exe') or m.path.endswith('.dll'):
                    try:
                        if os.path.exists(m.path):
                            with open(m.path, 'rb') as f:
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                                hashes.append({
                                    'module': os.path.basename(m.path),
                                    'sha256': file_hash[:16] + '...'
                                })
                    except:
                        pass
            return hashes
        except:
            return []
    
    def detect_debugger(self):
        """Erkennt ob ein Debugger attached ist"""
        if not self.process:
            return None
        
        try:
            # Prüft auf ungewöhnliche Thread-Anzahl oder Status
            threads = self.process.num_threads()
            status = self.process.status()
            
            suspicious = False
            if status == 'stopped' or status == 'tracing_stop':
                suspicious = True
            
            return {
                'status': status,
                'threads': threads,
                'suspicious': suspicious
            }
        except:
            return None
    
    def analyze_handle_count(self):
        """Analysiert Anzahl der offenen Handles"""
        if not self.process:
            return None
        
        try:
            handles = self.process.num_handles()
            fds = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
            
            return {
                'handles': handles,
                'file_descriptors': fds,
                'status': 'normal' if handles < 10000 else 'high'
            }
        except:
            return None
    
    def get_performance_metrics(self):
        """Sammelt umfassende Performance-Metriken"""
        if not self.process:
            return None
        
        try:
            cpu_times = self.process.cpu_times()
            mem_info = self.process.memory_info()
            
            return {
                'cpu_user': round(cpu_times.user, 2),
                'cpu_system': round(cpu_times.system, 2),
                'memory_rss_mb': round(mem_info.rss / 1024 / 1024, 2),
                'memory_vms_mb': round(mem_info.vms / 1024 / 1024, 2),
                'memory_percent': round(self.process.memory_percent(), 2)
            }
        except:
            return None
    
    def disassemble_entry_point(self):
        """Zeigt Entry-Point-Informationen der EXE"""
        if not self.process:
            return None
        
        try:
            exe_path = self.process.exe()
            if os.path.exists(exe_path):
                file_size = os.path.getsize(exe_path)
                with open(exe_path, 'rb') as f:
                    header = f.read(64)
                    dos_magic = header[:2]
                    
                return {
                    'path': exe_path,
                    'size_mb': round(file_size / 1024 / 1024, 2),
                    'dos_signature': dos_magic.hex(),
                    'is_pe': dos_magic == b'MZ'
                }
        except:
            return None
    
    def trace_syscalls(self, duration=3):
        """Trackt System-Calls über Zeit"""
        if not self.process:
            return None
        
        print(f"[*] Tracing syscalls for {duration} seconds...")
        samples = []
        
        try:
            for _ in range(duration):
                ctx_switches = self.process.num_ctx_switches()
                samples.append({
                    'voluntary': ctx_switches.voluntary,
                    'involuntary': ctx_switches.involuntary
                })
                time.sleep(1)
            
            return {
                'total_voluntary': sum(s['voluntary'] for s in samples),
                'total_involuntary': sum(s['involuntary'] for s in samples),
                'avg_per_sec': sum(s['voluntary'] + s['involuntary'] for s in samples) / duration
            }
        except:
            return None
    
    def analyze_code_sections(self):
        """Analysiert Code-Sections im Memory"""
        if not self.process:
            return None
        
        try:
            maps = self.process.memory_maps()
            code_sections = []
            
            for m in maps:
                perms = getattr(m, 'perms', '')
                if 'x' in perms.lower() or 'exec' in perms.lower():
                    code_sections.append({
                        'path': os.path.basename(m.path) if m.path else 'anonymous',
                        'size_kb': round(m.rss / 1024, 2),
                        'perms': perms
                    })
            
            return code_sections[:10]
        except:
            return []
    
    def detect_packed_executable(self):
        """Erkennt ob die EXE gepackt ist (UPX, etc.)"""
        if not self.process:
            return None
        
        try:
            exe_path = self.process.exe()
            if os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    data = f.read(1024 * 100)
                    
                packers = {
                    b'UPX': 'UPX Packer',
                    b'MPRESS': 'MPRESS',
                    b'PECompact': 'PECompact',
                    b'ASPack': 'ASPack',
                    b'Themida': 'Themida'
                }
                
                detected = []
                for sig, name in packers.items():
                    if sig in data:
                        detected.append(name)
                
                entropy = self._calculate_entropy(data[:1024])
                
                return {
                    'packers': detected if detected else ['None detected'],
                    'entropy': round(entropy, 2),
                    'likely_packed': entropy > 7.0 or len(detected) > 0
                }
        except:
            return None
    
    def _calculate_entropy(self, data):
        """Berechnet Shannon-Entropie"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy
    
    def monitor_registry_access(self):
        """Simuliert Registry-Access-Monitoring"""
        if not self.process:
            return None
        
        try:
            # Zeigt offene Handles (Windows-spezifisch)
            handles = self.process.num_handles()
            return {
                'total_handles': handles,
                'estimated_registry_handles': handles // 10,
                'note': 'Approximation based on handle count'
            }
        except:
            return None
    
    def analyze_import_table(self):
        """Analysiert Import-Table der EXE"""
        if not self.process:
            return None
        
        try:
            modules = self.process.memory_maps()
            dll_count = Counter()
            
            for m in modules:
                if m.path.endswith('.dll'):
                    dll_name = os.path.basename(m.path).lower()
                    dll_count[dll_name] += 1
            
            return dict(dll_count.most_common(10))
        except:
            return {}
    
    def detect_vm_sandbox(self):
        """Erkennt VM/Sandbox-Umgebung"""
        indicators = []
        
        try:
            # CPU-Check
            if psutil.cpu_count() <= 2:
                indicators.append('Low CPU count')
            
            # Memory-Check
            mem = psutil.virtual_memory()
            if mem.total < 4 * 1024 * 1024 * 1024:
                indicators.append('Low RAM')
            
            # Prozess-Check
            vm_processes = ['vboxservice', 'vmtoolsd', 'vmwaretray', 'vmwareuser']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in vm_processes:
                    indicators.append(f"VM Process: {proc.info['name']}")
            
            return {
                'indicators': indicators if indicators else ['None'],
                'likely_vm': len(indicators) > 0
            }
        except:
            return None
    
    def trace_api_calls(self):
        """Trackt häufige API-Calls (basierend auf DLL-Nutzung)"""
        if not self.process:
            return None
        
        try:
            modules = self.process.memory_maps()
            api_dlls = {
                'kernel32.dll': 'Process/Memory Management',
                'user32.dll': 'GUI/Window Management',
                'ntdll.dll': 'Native API',
                'ws2_32.dll': 'Network/Sockets',
                'advapi32.dll': 'Registry/Security',
                'gdi32.dll': 'Graphics',
                'opengl32.dll': 'OpenGL Graphics',
                'd3d11.dll': 'DirectX 11'
            }
            
            detected = []
            for m in modules:
                dll_name = os.path.basename(m.path).lower()
                if dll_name in api_dlls:
                    detected.append({
                        'dll': dll_name,
                        'category': api_dlls[dll_name],
                        'size_mb': round(m.rss / 1024 / 1024, 2)
                    })
            
            return detected
        except:
            return []
    
    def analyze_network_protocol(self):
        """Analysiert verwendete Netzwerk-Protokolle"""
        if not self.process:
            return None
        
        try:
            conns = self.process.connections()
            protocols = Counter()
            ports = Counter()
            
            for conn in conns:
                protocols[conn.type.name] += 1
                if conn.laddr:
                    ports[conn.laddr.port] += 1
            
            return {
                'protocols': dict(protocols),
                'top_ports': dict(ports.most_common(5))
            }
        except:
            return None
    
    def memory_forensics(self):
        """Führt Memory-Forensik durch"""
        if not self.process:
            return None
        
        try:
            mem_info = self.process.memory_info()
            maps = self.process.memory_maps()
            
            total_private = sum(m.private for m in maps if hasattr(m, 'private'))
            total_shared = sum(m.shared for m in maps if hasattr(m, 'shared'))
            
            return {
                'rss_mb': round(mem_info.rss / 1024 / 1024, 2),
                'vms_mb': round(mem_info.vms / 1024 / 1024, 2),
                'private_mb': round(total_private / 1024 / 1024, 2) if total_private else 0,
                'shared_mb': round(total_shared / 1024 / 1024, 2) if total_shared else 0,
                'regions': len(maps)
            }
        except:
            return None
    
    def realtime_monitor(self, duration=5):
        """Echtzeit-Monitoring aller Metriken"""
        if not self.process:
            return None
        
        print(f"[*] Real-time monitoring for {duration} seconds...")
        samples = []
        
        try:
            for i in range(duration):
                sample = {
                    'time': i,
                    'cpu': self.process.cpu_percent(interval=0.1),
                    'memory_mb': self.process.memory_info().rss / 1024 / 1024,
                    'threads': self.process.num_threads(),
                    'connections': len(self.process.connections())
                }
                samples.append(sample)
                print(f"  [{i+1}/{duration}] CPU: {sample['cpu']:.1f}% | MEM: {sample['memory_mb']:.1f}MB | Threads: {sample['threads']}")
                time.sleep(1)
            
            return {
                'avg_cpu': round(sum(s['cpu'] for s in samples) / len(samples), 2),
                'avg_memory_mb': round(sum(s['memory_mb'] for s in samples) / len(samples), 2),
                'peak_memory_mb': round(max(s['memory_mb'] for s in samples), 2)
            }
        except:
            return None
    
    def deep_memory_scanner(self):
        """Scannt Memory nach interessanten Patterns"""
        if not self.process:
            return None
        
        print("[*] Scanning memory regions for patterns...")
        try:
            maps = self.process.memory_maps()
            findings = []
            
            patterns = {
                'lua_state': b'Lua',
                'http': b'http://',
                'https': b'https://',
                'json': b'{"',
                'xml': b'<?xml',
                'api': b'api.roblox'
            }
            
            for m in maps[:30]:
                if m.path and os.path.exists(m.path):
                    try:
                        with open(m.path, 'rb') as f:
                            data = f.read(1024 * 100)
                            for name, pattern in patterns.items():
                                if pattern in data:
                                    findings.append({
                                        'type': name,
                                        'region': os.path.basename(m.path),
                                        'size': m.rss / 1024,
                                        'offset': data.find(pattern)
                                    })
                    except:
                        pass
            
            return findings[:20]
        except:
            return []
    
    def x_module(self):
        """Advanced analysis module"""
        if not self.process:
            return None
        
        try:
            data = {
                'process_id': self.pid,
                'parent_pid': self.process.ppid(),
                'create_time': datetime.fromtimestamp(self.process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'username': self.process.username(),
                'nice': self.process.nice() if hasattr(self.process, 'nice') else 'N/A',
                'ionice': 'N/A'
            }
            
            try:
                children = self.process.children()
                data['child_processes'] = len(children)
                data['children'] = [{'pid': c.pid, 'name': c.name()} for c in children[:5]]
            except:
                data['child_processes'] = 0
                data['children'] = []
            
            try:
                open_files = self.process.open_files()
                data['open_files'] = len(open_files)
                data['files'] = [f.path for f in open_files[:10]]
            except:
                data['open_files'] = 0
                data['files'] = []
            
            try:
                cwd = self.process.cwd()
                data['working_directory'] = cwd
            except:
                data['working_directory'] = 'N/A'
            
            try:
                cmdline = self.process.cmdline()
                data['command_line'] = ' '.join(cmdline)
            except:
                data['command_line'] = 'N/A'
            
            return data
        except:
            return None
    
    def alpha_function(self):
        if not self.process:
            return None
        try:
            net_io = psutil.net_io_counters()
            disk_io = psutil.disk_io_counters()
            cpu_freq = psutil.cpu_freq()
            
            return {
                'net_sent_mb': round(net_io.bytes_sent / 1024 / 1024, 2),
                'net_recv_mb': round(net_io.bytes_recv / 1024 / 1024, 2),
                'disk_read_mb': round(disk_io.read_bytes / 1024 / 1024, 2),
                'disk_write_mb': round(disk_io.write_bytes / 1024 / 1024, 2),
                'cpu_freq_mhz': round(cpu_freq.current, 2) if cpu_freq else 0,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
        except:
            return None
    
    def beta_function(self):
        if not self.process:
            return None
        try:
            affinity = self.process.cpu_affinity()
            mem_maps = self.process.memory_maps(grouped=False)
            
            executable_regions = [m for m in mem_maps if 'x' in getattr(m, 'perms', '').lower()]
            writable_regions = [m for m in mem_maps if 'w' in getattr(m, 'perms', '').lower()]
            
            return {
                'cpu_affinity': affinity,
                'total_regions': len(mem_maps),
                'executable_regions': len(executable_regions),
                'writable_regions': len(writable_regions),
                'exe_size_mb': sum(m.rss for m in executable_regions) / 1024 / 1024,
                'write_size_mb': sum(m.rss for m in writable_regions) / 1024 / 1024
            }
        except:
            return None
    
    def gamma_function(self):
        if not self.process:
            return None
        try:
            conns = self.process.connections()
            
            established = [c for c in conns if c.status == 'ESTABLISHED']
            listening = [c for c in conns if c.status == 'LISTEN']
            
            remote_ips = list(set([c.raddr.ip for c in established if c.raddr]))
            
            bandwidth_estimate = len(established) * 0.5
            
            return {
                'total_connections': len(conns),
                'established': len(established),
                'listening': len(listening),
                'unique_ips': len(remote_ips),
                'remote_ips': remote_ips[:10],
                'bandwidth_estimate_mbps': round(bandwidth_estimate, 2)
            }
        except:
            return None
    
    def extract_game_servers(self):
        """Extrahiert Game-Server aus Netzwerk-Verbindungen"""
        if not self.process:
            return None
        
        try:
            conns = self.process.connections()
            servers = []
            
            for conn in conns:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    
                    # Roblox-Server sind meist auf bestimmten Ports
                    if port >= 50000 or (port >= 443 and port <= 53640):
                        try:
                            hostname = socket.getfqdn(ip)
                        except:
                            hostname = 'Unknown'
                        
                        servers.append({
                            'ip': ip,
                            'port': port,
                            'hostname': hostname,
                            'join_link': f"roblox://placeId=0&gameInstanceId={ip}:{port}"
                        })
            
            return servers
        except:
            return []

def main():
    print("=" * 60)
    print("🎮 ROBLOX REVERSE ENGINEERING TOOL 🎮")
    print("=" * 60)
    
    tool = RobloxTool()
    
    while True:
        print("\n[MENU - REVERSE ENGINEERING]")
        print("1. Find Roblox Process")
        print("2. Process Info")
        print("3. Monitor Network")
        print("4. Memory Regions")
        print("5. Scan Memory Pattern")
        print("6. Dump Strings")
        print("7. Loaded Modules")
        print("\n[ADVANCED REVERSE ENGINEERING]")
        print("15. Thread Activity Analysis")
        print("16. I/O Operations Monitor")
        print("17. Detect Anti-Cheat")
        print("18. Memory Protection Analysis")
        print("19. Network Bandwidth Tracker")
        print("20. Environment Variables")
        print("21. Module Hash Calculator")
        print("22. Debugger Detection")
        print("23. Handle Count Analysis")
        print("24. Performance Metrics")
        print("\n[EXTREME REVERSE ENGINEERING]")
        print("25. Entry Point Analysis")
        print("26. Syscall Tracer")
        print("27. Code Section Analysis")
        print("28. Packed Executable Detection")
        print("29. Registry Access Monitor")
        print("30. Import Table Analysis")
        print("31. VM/Sandbox Detection")
        print("32. API Call Tracer")
        print("33. Network Protocol Analysis")
        print("34. Memory Forensics")
        print("35. Real-time Monitor")
        print("36. Extract Game Servers")
        print("40. Deep Memory Scanner 🔥")
        print("41. ??? 🔒")
        print("42. α ⚡")
        print("43. β 🛡️")
        print("44. γ 🌐")
        print("\n[GAME FEATURES]")
        print("37. Game Info Lookup")
        print("38. Active Game Servers")
        print("\n[MENU - ROBLOX API]")
        print("8. User Info")
        print("9. Friends Count")
        print("10. Friends List")
        print("11. User Badges")
        print("12. User Games")
        print("13. User Presence")
        print("14. Search Users")
        print("39. Get Player Server Link 🔥")
        print("45. δ 👤")
        print("46. ε 🏘️")
        print("47. ζ 🎒")
        print("48. Ω ULTIMATE 💀")
        print("\n0. Exit")
        
        choice = input("\n> Select: ")
        
        if choice == "1":
            if tool.find_roblox_process():
                print(f"✓ Roblox found! PID: {tool.pid}")
            else:
                print("✗ Roblox not running")
        
        elif choice == "2":
            info = tool.get_process_info()
            if info:
                print(json.dumps(info, indent=2))
            else:
                print("✗ Find process first")
        
        elif choice == "3":
            conns = tool.monitor_network()
            print(f"\n[*] Active connections: {len(conns)}")
            for c in conns:
                print(f"  → {c['remote_ip']}:{c['remote_port']}")
        
        elif choice == "4":
            regions = tool.get_memory_regions()
            print(f"\n[*] Memory regions (top 10):")
            for r in regions:
                print(f"  {r['size_mb']:.2f} MB - {r['path']}")
        
        elif choice == "5":
            pattern = input("Pattern (hex): ")
            results = tool.scan_memory_pattern(pattern)
            for r in results:
                print(f"  {r}")
        
        elif choice == "6":
            strings = tool.dump_strings()
            if strings:
                print(f"\n[*] Found {len(strings)} relevant strings:")
                for s in strings:
                    print(f"  {s}")
            else:
                print("✗ No strings found or process not running")
        
        elif choice == "7":
            modules = tool.get_loaded_modules()
            print(f"\n[*] Loaded modules ({len(modules)}):")
            for m in modules[:10]:
                print(f"  {m}")
        
        elif choice == "8":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                info = tool.api.get_user_info(user['id'])
                print(f"\n👤 {info['displayName']} (@{info['name']})")
                print(f"   ID: {info['id']}")
                print(f"   Created: {info['created'][:10]}")
                print(f"   Description: {info['description'][:100] if info.get('description') else 'N/A'}")
            else:
                print("✗ User not found")
        
        elif choice == "9":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                count = tool.api.get_friends_count(user['id'])
                print(f"\n👥 {username} hat {count} Freunde")
            else:
                print("✗ User not found")
        
        elif choice == "10":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                friends = tool.api.get_friends_list(user['id'])
                print(f"\n👥 Freunde ({len(friends)}):")
                for f in friends[:20]:
                    print(f"  • {f['displayName']} (@{f['name']})")
            else:
                print("✗ User not found")
        
        elif choice == "11":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                badges = tool.api.get_user_badges(user['id'])
                print(f"\n🏆 Badges ({len(badges)}):")
                for b in badges[:15]:
                    print(f"  • {b['name']}")
            else:
                print("✗ User not found")
        
        elif choice == "12":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                games = tool.api.get_user_games(user['id'])
                print(f"\n🎮 Games ({len(games)}):")
                for g in games:
                    print(f"  • {g['name']}")
            else:
                print("✗ User not found")
        
        elif choice == "13":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                presence = tool.api.get_user_presence(user['id'])
                if presence:
                    status = presence.get('userPresenceType', 0)
                    status_text = ['Offline', 'Online', 'In Game', 'In Studio'][status]
                    print(f"\n🟢 Status: {status_text}")
                    if presence.get('lastLocation'):
                        print(f"   Location: {presence['lastLocation']}")
            else:
                print("✗ User not found")
        
        elif choice == "14":
            keyword = input("Search: ")
            users = tool.api.search_users(keyword)
            print(f"\n🔍 Results ({len(users)}):")
            for u in users:
                print(f"  • {u['displayName']} (@{u['name']})")
        
        elif choice == "15":
            threads = tool.analyze_thread_activity()
            if threads:
                print(f"\n🧵 Thread Activity (Top 10):")
                for t in threads:
                    print(f"  Thread {t['id']}: User={t['user_time']}s, System={t['system_time']}s")
            else:
                print("✗ Find process first")
        
        elif choice == "16":
            io = tool.monitor_io_operations()
            if io:
                print(f"\n💾 I/O Operations (per second):")
                print(f"  Read: {io['read_bytes_sec']} bytes ({io['read_count']} ops)")
                print(f"  Write: {io['write_bytes_sec']} bytes ({io['write_count']} ops)")
            else:
                print("✗ Find process first")
        
        elif choice == "17":
            ac = tool.detect_anti_cheat()
            if ac:
                print(f"\n🛡️ Anti-Cheat Detected ({len(ac)}):")
                for a in ac:
                    print(f"  • {a['module']} ({a['size_mb']:.2f} MB)")
            else:
                print("✓ No anti-cheat modules detected")
        
        elif choice == "18":
            prot = tool.analyze_memory_protection()
            if prot:
                print(f"\n🔒 Memory Protection Stats:")
                for k, v in prot.items():
                    print(f"  {k}: {v} regions")
            else:
                print("✗ Find process first")
        
        elif choice == "19":
            bw = tool.track_network_bandwidth()
            if bw:
                print(f"\n📊 Network Bandwidth:")
                print(f"  Avg Connections: {bw['avg_connections']:.1f}")
                print(f"  Max Connections: {bw['max_connections']}")
                print(f"  Min Connections: {bw['min_connections']}")
            else:
                print("✗ Find process first")
        
        elif choice == "20":
            env = tool.get_environment_variables()
            if env:
                print(f"\n🌍 Environment Variables:")
                for k, v in env.items():
                    print(f"  {k}: {v}")
            else:
                print("✗ Find process first")
        
        elif choice == "21":
            hashes = tool.calculate_module_hashes()
            if hashes:
                print(f"\n#️⃣ Module Hashes (Top 5):")
                for h in hashes:
                    print(f"  {h['module']}: {h['sha256']}")
            else:
                print("✗ Find process first")
        
        elif choice == "22":
            dbg = tool.detect_debugger()
            if dbg:
                print(f"\n🐛 Debugger Detection:")
                print(f"  Status: {dbg['status']}")
                print(f"  Threads: {dbg['threads']}")
                print(f"  Suspicious: {'⚠️ YES' if dbg['suspicious'] else '✓ NO'}")
            else:
                print("✗ Find process first")
        
        elif choice == "23":
            handles = tool.analyze_handle_count()
            if handles:
                print(f"\n🔧 Handle Analysis:")
                print(f"  Handles: {handles['handles']}")
                print(f"  File Descriptors: {handles['file_descriptors']}")
                print(f"  Status: {handles['status']}")
            else:
                print("✗ Find process first")
        
        elif choice == "24":
            perf = tool.get_performance_metrics()
            if perf:
                print(f"\n⚡ Performance Metrics:")
                print(f"  CPU User Time: {perf['cpu_user']}s")
                print(f"  CPU System Time: {perf['cpu_system']}s")
                print(f"  Memory RSS: {perf['memory_rss_mb']} MB")
                print(f"  Memory VMS: {perf['memory_vms_mb']} MB")
                print(f"  Memory %: {perf['memory_percent']}%")
            else:
                print("✗ Find process first")
        
        elif choice == "25":
            ep = tool.disassemble_entry_point()
            if ep:
                print(f"\n🎯 Entry Point Analysis:")
                print(f"  Path: {ep['path']}")
                print(f"  Size: {ep['size_mb']} MB")
                print(f"  DOS Signature: {ep['dos_signature']}")
                print(f"  Valid PE: {'✓ YES' if ep['is_pe'] else '✗ NO'}")
            else:
                print("✗ Find process first")
        
        elif choice == "26":
            syscalls = tool.trace_syscalls()
            if syscalls:
                print(f"\n🔄 Syscall Trace:")
                print(f"  Voluntary Switches: {syscalls['total_voluntary']}")
                print(f"  Involuntary Switches: {syscalls['total_involuntary']}")
                print(f"  Avg per Second: {syscalls['avg_per_sec']:.1f}")
            else:
                print("✗ Find process first")
        
        elif choice == "27":
            sections = tool.analyze_code_sections()
            if sections:
                print(f"\n📝 Code Sections ({len(sections)}):")
                for s in sections:
                    print(f"  {s['path']}: {s['size_kb']} KB [{s['perms']}]")
            else:
                print("✗ Find process first")
        
        elif choice == "28":
            packed = tool.detect_packed_executable()
            if packed:
                print(f"\n📦 Packer Detection:")
                print(f"  Detected: {', '.join(packed['packers'])}")
                print(f"  Entropy: {packed['entropy']}")
                print(f"  Likely Packed: {'⚠️ YES' if packed['likely_packed'] else '✓ NO'}")
            else:
                print("✗ Find process first")
        
        elif choice == "29":
            reg = tool.monitor_registry_access()
            if reg:
                print(f"\n📋 Registry Access:")
                print(f"  Total Handles: {reg['total_handles']}")
                print(f"  Est. Registry Handles: {reg['estimated_registry_handles']}")
                print(f"  Note: {reg['note']}")
            else:
                print("✗ Find process first")
        
        elif choice == "30":
            imports = tool.analyze_import_table()
            if imports:
                print(f"\n📚 Import Table (Top 10 DLLs):")
                for dll, count in imports.items():
                    print(f"  {dll}: {count} references")
            else:
                print("✗ Find process first")
        
        elif choice == "31":
            vm = tool.detect_vm_sandbox()
            if vm:
                print(f"\n🖥️ VM/Sandbox Detection:")
                print(f"  Indicators: {', '.join(vm['indicators'])}")
                print(f"  Likely VM: {'⚠️ YES' if vm['likely_vm'] else '✓ NO'}")
            else:
                print("✗ Detection failed")
        
        elif choice == "32":
            apis = tool.trace_api_calls()
            if apis:
                print(f"\n🔌 API Call Trace ({len(apis)} DLLs):")
                for api in apis:
                    print(f"  {api['dll']}: {api['category']} ({api['size_mb']} MB)")
            else:
                print("✗ Find process first")
        
        elif choice == "33":
            proto = tool.analyze_network_protocol()
            if proto:
                print(f"\n🌐 Network Protocol Analysis:")
                print(f"  Protocols: {proto['protocols']}")
                print(f"  Top Ports: {proto['top_ports']}")
            else:
                print("✗ Find process first")
        
        elif choice == "34":
            forensics = tool.memory_forensics()
            if forensics:
                print(f"\n🔬 Memory Forensics:")
                print(f"  RSS: {forensics['rss_mb']} MB")
                print(f"  VMS: {forensics['vms_mb']} MB")
                print(f"  Private: {forensics['private_mb']} MB")
                print(f"  Shared: {forensics['shared_mb']} MB")
                print(f"  Regions: {forensics['regions']}")
            else:
                print("✗ Find process first")
        
        elif choice == "35":
            monitor = tool.realtime_monitor()
            if monitor:
                print(f"\n📈 Real-time Summary:")
                print(f"  Avg CPU: {monitor['avg_cpu']}%")
                print(f"  Avg Memory: {monitor['avg_memory_mb']} MB")
                print(f"  Peak Memory: {monitor['peak_memory_mb']} MB")
            else:
                print("✗ Find process first")
        
        elif choice == "36":
            servers = tool.extract_game_servers()
            if servers:
                print(f"\n🎮 Game Servers Detected ({len(servers)}):")
                for i, s in enumerate(servers, 1):
                    print(f"\n  Server {i}:")
                    print(f"    IP: {s['ip']}:{s['port']}")
                    print(f"    Hostname: {s['hostname']}")
                    print(f"    Join Link: {s['join_link']}")
                    print(f"    (Copy link and paste in browser to join)")
            else:
                print("✗ No servers detected or process not found")
        
        elif choice == "37":
            place_id = input("Place ID: ")
            game = tool.api.get_game_info(place_id)
            if game:
                print(f"\n🎮 Game Info:")
                print(f"  Name: {game.get('name', 'N/A')}")
                print(f"  Description: {game.get('description', 'N/A')[:100]}")
                print(f"  Place ID: {game.get('placeId', 'N/A')}")
                print(f"  Builder: {game.get('builder', 'N/A')}")
                print(f"  Join Link: roblox://placeId={place_id}")
            else:
                print("✗ Game not found")
        
        elif choice == "38":
            place_id = input("Place ID: ")
            servers = tool.api.get_game_servers(place_id)
            if servers:
                print(f"\n🔥 Active Servers ({len(servers)}):")
                for i, s in enumerate(servers, 1):
                    print(f"\n  Server {i}:")
                    print(f"    ID: {s.get('id', 'N/A')}")
                    print(f"    Players: {s.get('playing', 0)}/{s.get('maxPlayers', 0)}")
                    print(f"    FPS: {s.get('fps', 'N/A')}")
                    print(f"    Ping: {s.get('ping', 'N/A')}ms")
            else:
                print("✗ No servers found")
        
        elif choice == "39":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                print(f"\n[*] Checking {username}'s game status...")
                data = tool.api.get_player_server_link(user['id'])
                
                if data:
                    if data.get('error'):
                        print(f"\n✗ Error: {data['error']}")
                        print(f"\n💡 Tipps:")
                        print(f"   1. Prüfe deine Internetverbindung")
                        print(f"   2. Versuche einen anderen DNS-Server (z.B. 8.8.8.8)")
                        print(f"   3. Deaktiviere VPN/Proxy falls aktiv")
                        print(f"   4. Prüfe ob roblox.com im Browser erreichbar ist")
                    elif not data.get('in_game'):
                        print(f"✗ {username} is not in a game")
                        print(f"   Status: {data.get('status', 'Unknown')}")
                    else:
                        print(f"\n🎮 {username} is playing!")
                        print(f"   Game: {data['game_name']}")
                        print(f"   Place ID: {data['place_id']}")
                        if data.get('game_id'):
                            print(f"   Instance ID: {data['game_id']}")
                        print(f"\n🔗 Server Link:")
                        print(f"   {data['server_link']}")
                        print(f"\n🌐 Web Link:")
                        print(f"   {data['web_link']}")
                        print(f"\nℹ️ Copy the server link and paste in browser to join!")
                else:
                    print("✗ Could not fetch data")
            else:
                print("✗ User not found")
        
        elif choice == "40":
            findings = tool.deep_memory_scanner()
            if findings:
                print(f"\n🔍 Deep Memory Scan Results ({len(findings)}):")
                for f in findings:
                    print(f"  [{f['type']}] {f['region']}: {f['size']:.1f} KB @ offset {f['offset']}")
            else:
                print("✗ Find process first or no patterns found")
        
        elif choice == "41":
            result = tool.x_module()
            if result:
                print(f"\n🔒 Advanced Process Analysis:")
                print(f"  PID: {result['process_id']}")
                print(f"  Parent PID: {result['parent_pid']}")
                print(f"  Created: {result['create_time']}")
                print(f"  User: {result['username']}")
                print(f"  Working Dir: {result['working_directory']}")
                print(f"  Child Processes: {result['child_processes']}")
                if result['children']:
                    for c in result['children']:
                        print(f"    • {c['name']} (PID: {c['pid']})")
                print(f"  Open Files: {result['open_files']}")
                if result['files']:
                    for f in result['files'][:5]:
                        print(f"    • {f}")
                print(f"  Command: {result['command_line'][:100]}")
            else:
                print("✗ Find process first")
        
        elif choice == "42":
            result = tool.alpha_function()
            if result:
                print(f"\n⚡ System Statistics:")
                print(f"  Network Sent: {result['net_sent_mb']} MB")
                print(f"  Network Received: {result['net_recv_mb']} MB")
                print(f"  Disk Read: {result['disk_read_mb']} MB")
                print(f"  Disk Write: {result['disk_write_mb']} MB")
                print(f"  CPU Frequency: {result['cpu_freq_mhz']} MHz")
                print(f"  System Boot: {result['boot_time']}")
            else:
                print("✗ Find process first")
        
        elif choice == "43":
            result = tool.beta_function()
            if result:
                print(f"\n🛡️ Memory Region Analysis:")
                print(f"  CPU Affinity: {result['cpu_affinity']}")
                print(f"  Total Regions: {result['total_regions']}")
                print(f"  Executable Regions: {result['executable_regions']}")
                print(f"  Writable Regions: {result['writable_regions']}")
                print(f"  Executable Size: {result['exe_size_mb']:.2f} MB")
                print(f"  Writable Size: {result['write_size_mb']:.2f} MB")
            else:
                print("✗ Find process first")
        
        elif choice == "44":
            result = tool.gamma_function()
            if result:
                print(f"\n🌐 Network Connection Analysis:")
                print(f"  Total Connections: {result['total_connections']}")
                print(f"  Established: {result['established']}")
                print(f"  Listening: {result['listening']}")
                print(f"  Unique Remote IPs: {result['unique_ips']}")
                print(f"  Bandwidth Estimate: {result['bandwidth_estimate_mbps']} Mbps")
                if result['remote_ips']:
                    print(f"  Remote IPs:")
                    for ip in result['remote_ips']:
                        print(f"    • {ip}")
            else:
                print("✗ Find process first")
        
        elif choice == "45":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                data = tool.api.delta_func(user['id'])
                if data:
                    print(f"\n👤 Avatar:")
                    print(f"  User: {username}")
                    print(f"  Image URL: {data.get('imageUrl', 'N/A')}")
                    print(f"  State: {data.get('state', 'N/A')}")
                else:
                    print("✗ No data")
            else:
                print("✗ User not found")
        
        elif choice == "46":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                groups = tool.api.epsilon_func(user['id'])
                if groups:
                    print(f"\n🏘️ Groups ({len(groups)}):")
                    for g in groups[:10]:
                        grp = g.get('group', {})
                        role = g.get('role', {})
                        print(f"  • {grp.get('name', 'N/A')} [{role.get('name', 'Member')}]")
                        print(f"    Members: {grp.get('memberCount', 0)}")
                else:
                    print("✗ No groups")
            else:
                print("✗ User not found")
        
        elif choice == "47":
            username = input("Username: ")
            user = tool.api.get_user_by_username(username)
            if user:
                items = tool.api.zeta_func(user['id'])
                if items:
                    print(f"\n🎒 Collectibles ({len(items)}):")
                    for item in items:
                        print(f"  • {item.get('name', 'N/A')}")
                        if item.get('recentAveragePrice'):
                            print(f"    Price: {item['recentAveragePrice']} R$")
                else:
                    print("✗ No items")
            else:
                print("✗ User not found")
        
        elif choice == "48":
            username = input("Target: ")
            print(f"\n[*] Tracking...")
            d = tool.api.omega_tracker(username)
            if d:
                print(f"\n💀 ULTIMATE TRACKER")
                print(f"\n📋 INFO:")
                print(f"  User: {d['username']} ({d['display_name']})")
                print(f"  ID: {d['user_id']}")
                print(f"  Created: {d['created']}")
                print(f"  Banned: {'⚠️ YES' if d.get('banned') else '✓ NO'}")
                print(f"\n👥 SOCIAL:")
                print(f"  Friends: {d['friends']}")
                print(f"  Groups: {d['groups']}")
                print(f"\n🎮 ACTIVITY:")
                print(f"  Status: {d.get('status', 'Unknown')}")
                if d.get('game'):
                    print(f"\n🔥 PLAYING NOW:")
                    print(f"  Place: {d['game']}")
                    if d.get('instance'):
                        print(f"  Instance: {d['instance']}")
                    print(f"  Join: {d.get('link')}")
            else:
                print("✗ Failed")
        
        elif choice == "0":
            print("\n[*] Exiting...")
            break
        
        else:
            print("✗ Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n\n✗ Error: {e}")
    finally:
        input("\nPress ENTER to exit...")
