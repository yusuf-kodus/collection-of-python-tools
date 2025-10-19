import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from bs4 import BeautifulSoup
import threading
import time
import json
import re
from urllib.parse import urlparse, urljoin
import socket
import ssl
import whois
from datetime import datetime

class WebsiteTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze_website(self, url):
        """Analysiert Website"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'size': len(response.content),
                'title': soup.title.string if soup.title else 'Kein Titel',
                'links': len(soup.find_all('a')),
                'images': len(soup.find_all('img')),
                'scripts': len(soup.find_all('script')),
                'forms': len(soup.find_all('form')),
                'headers': dict(response.headers)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_links(self, url):
        """Extrahiert alle Links"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            links = []
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                links.append({
                    'text': link.get_text(strip=True)[:50],
                    'url': full_url
                })
            return links
        except Exception as e:
            return []
    
    def extract_images(self, url):
        """Extrahiert alle Bilder"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            images = []
            for img in soup.find_all('img'):
                src = img.get('src', '')
                if src:
                    full_url = urljoin(url, src)
                    images.append({
                        'alt': img.get('alt', 'Kein Alt-Text'),
                        'url': full_url
                    })
            return images
        except Exception as e:
            return []
    
    def check_security(self, url):
        """Prüft Sicherheit"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            # SSL Check
            ssl_info = {}
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'valid_from': cert['notBefore'],
                            'valid_until': cert['notAfter'],
                            'version': cert['version']
                        }
            
            # Headers Check
            response = self.session.get(url, timeout=10)
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Nicht gesetzt'),
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'Nicht gesetzt'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Nicht gesetzt'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Nicht gesetzt')
            }
            
            return {
                'https': parsed.scheme == 'https',
                'ssl_info': ssl_info,
                'security_headers': security_headers
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_whois_info(self, url):
        """Holt WHOIS Informationen"""
        try:
            domain = urlparse(url).hostname
            w = whois.whois(domain)
            return {
                'domain': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            return {'error': str(e)}
    
    def download_website(self, url, save_path):
        """Lädt Website herunter"""
        try:
            response = self.session.get(url, timeout=10)
            with open(save_path, 'wb') as f:
                f.write(response.content)
            return True
        except:
            return False
    
    def find_emails(self, url):
        """Findet E-Mail-Adressen"""
        try:
            response = self.session.get(url, timeout=10)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            return list(set(emails))
        except:
            return []
    
    def find_phone_numbers(self, url):
        """Findet Telefonnummern"""
        try:
            response = self.session.get(url, timeout=10)
            phones = re.findall(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}', response.text)
            return list(set(phones))[:20]
        except:
            return []
    
    def get_meta_tags(self, url):
        """Extrahiert Meta-Tags"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            return meta_tags
        except:
            return {}
    
    def check_technologies(self, url):
        """Erkennt verwendete Technologien"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            techs = []
            
            # JavaScript Frameworks
            if 'react' in response.text.lower():
                techs.append('React')
            if 'vue' in response.text.lower():
                techs.append('Vue.js')
            if 'angular' in response.text.lower():
                techs.append('Angular')
            if 'jquery' in response.text.lower():
                techs.append('jQuery')
            
            # CMS
            if 'wp-content' in response.text:
                techs.append('WordPress')
            if 'joomla' in response.text.lower():
                techs.append('Joomla')
            
            # Server
            server = response.headers.get('Server', '')
            if server:
                techs.append(f'Server: {server}')
            
            return techs
        except:
            return []
    
    def screenshot_website(self, url, save_path):
        """Macht Screenshot der Website"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            time.sleep(2)
            driver.save_screenshot(save_path)
            driver.quit()
            return True
        except:
            return False
    
    def get_page_speed(self, url):
        """Misst Ladegeschwindigkeit"""
        try:
            times = []
            for _ in range(3):
                start = time.time()
                response = self.session.get(url, timeout=10)
                end = time.time()
                times.append(end - start)
            
            return {
                'min': min(times),
                'max': max(times),
                'avg': sum(times) / len(times)
            }
        except:
            return None
    
    def check_broken_links(self, url):
        """Prüft auf defekte Links"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            broken = []
            for link in soup.find_all('a', href=True)[:50]:
                full_url = urljoin(url, link['href'])
                try:
                    r = self.session.head(full_url, timeout=5)
                    if r.status_code >= 400:
                        broken.append({'url': full_url, 'status': r.status_code})
                except:
                    broken.append({'url': full_url, 'status': 'Timeout/Error'})
            
            return broken
        except:
            return []
    
    def get_seo_analysis(self, url):
        """SEO Analyse"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            seo = {}
            
            # Title
            title = soup.find('title')
            seo['title'] = title.string if title else 'Fehlt'
            seo['title_length'] = len(title.string) if title else 0
            
            # Meta Description
            desc = soup.find('meta', attrs={'name': 'description'})
            seo['description'] = desc.get('content') if desc else 'Fehlt'
            seo['description_length'] = len(desc.get('content', '')) if desc else 0
            
            # Headings
            seo['h1_count'] = len(soup.find_all('h1'))
            seo['h2_count'] = len(soup.find_all('h2'))
            
            # Images without alt
            images = soup.find_all('img')
            seo['images_total'] = len(images)
            seo['images_without_alt'] = len([img for img in images if not img.get('alt')])
            
            # Canonical
            canonical = soup.find('link', attrs={'rel': 'canonical'})
            seo['canonical'] = canonical.get('href') if canonical else 'Fehlt'
            
            return seo
        except:
            return {}
    
    def get_social_media_links(self, url):
        """Findet Social Media Links"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            social = {}
            platforms = {
                'facebook': 'facebook.com',
                'twitter': 'twitter.com',
                'instagram': 'instagram.com',
                'linkedin': 'linkedin.com',
                'youtube': 'youtube.com',
                'tiktok': 'tiktok.com'
            }
            
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                for platform, domain in platforms.items():
                    if domain in href:
                        social[platform] = link['href']
            
            return social
        except:
            return {}
    
    def get_cookies(self, url):
        """Zeigt Cookies"""
        try:
            response = self.session.get(url, timeout=10)
            cookies = []
            for cookie in response.cookies:
                cookies.append({
                    'name': cookie.name,
                    'value': cookie.value[:50],
                    'domain': cookie.domain,
                    'path': cookie.path
                })
            return cookies
        except:
            return []
    
    def get_robots_txt(self, url):
        """Holt robots.txt"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                return response.text
            return "Nicht gefunden"
        except:
            return "Fehler beim Abrufen"
    
    def get_sitemap(self, url):
        """Holt sitemap.xml"""
        try:
            parsed = urlparse(url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=10)
            if response.status_code == 200:
                return response.text[:5000]
            return "Nicht gefunden"
        except:
            return "Fehler beim Abrufen"

class WebsiteToolGUI:
    def __init__(self):
        self.tool = WebsiteTool()
        
        self.window = tk.Tk()
        self.window.title("Website Analyse Tool")
        self.window.geometry("1000x750")
        self.window.configure(bg="#1a1a1a")
        
        # Header
        header = tk.Frame(self.window, bg="#2d2d2d", height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        tk.Label(header, text="🌐 Website Analyse Tool", font=("Arial", 18, "bold"),
                bg="#2d2d2d", fg="#00bfff").pack(pady=15)
        
        # URL Input
        url_frame = tk.Frame(self.window, bg="#1a1a1a")
        url_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(url_frame, text="URL:", bg="#1a1a1a", fg="white", font=("Arial", 11)).pack(side="left", padx=5)
        self.url_entry = tk.Entry(url_frame, width=60, font=("Arial", 11))
        self.url_entry.pack(side="left", padx=5)
        self.url_entry.insert(0, "https://example.com")
        
        tk.Button(url_frame, text="🔍 Analysieren", command=self.analyze,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        
        # Tabs
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: Analyse
        tab1 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab1, text="Analyse")
        self.create_analysis_tab(tab1)
        
        # Tab 2: Links
        tab2 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab2, text="Links")
        self.create_links_tab(tab2)
        
        # Tab 3: Sicherheit
        tab3 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab3, text="Sicherheit")
        self.create_security_tab(tab3)
        
        # Tab 4: Extrahieren
        tab4 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab4, text="Extrahieren")
        self.create_extract_tab(tab4)
        
        # Tab 5: SEO
        tab5 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab5, text="SEO")
        self.create_seo_tab(tab5)
        
        # Tab 6: Tools
        tab6 = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(tab6, text="Tools")
        self.create_tools_tab(tab6)
        
        self.window.mainloop()
    
    def create_analysis_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📊 Vollständige Analyse", command=self.full_analysis,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🔧 Technologien", command=self.check_tech,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        
        self.analysis_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                        font=("Consolas", 9))
        self.analysis_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_links_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔗 Links extrahieren", command=self.extract_links,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🖼️ Bilder extrahieren", command=self.extract_images,
                 bg="#00BCD4", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        
        self.links_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                     font=("Consolas", 9))
        self.links_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_security_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔒 Sicherheit prüfen", command=self.check_security,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📋 WHOIS Info", command=self.get_whois,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        
        self.security_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                        font=("Consolas", 9))
        self.security_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_extract_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📧 E-Mails finden", command=self.find_emails,
                 bg="#FF5722", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📞 Telefonnummern", command=self.find_phones,
                 bg="#00BCD4", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🏷️ Meta-Tags", command=self.get_meta,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold"), width=20).pack(side="left", padx=5)
        
        self.extract_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                       font=("Consolas", 9))
        self.extract_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_seo_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📊 SEO Analyse", command=self.seo_analysis,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=18).pack(side="left", padx=5)
        tk.Button(btn_frame, text="🐞 Defekte Links", command=self.check_broken,
                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), width=18).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📱 Social Media", command=self.find_social,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold"), width=18).pack(side="left", padx=5)
        
        self.seo_text = scrolledtext.ScrolledText(parent, height=25, bg="#2d2d2d", fg="#00ff00",
                                                   font=("Consolas", 9))
        self.seo_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def create_tools_tab(self, parent):
        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(pady=15)
        
        row1 = tk.Frame(btn_frame, bg="#1a1a1a")
        row1.pack(pady=5)
        
        tk.Button(row1, text="💾 Website herunterladen", command=self.download_site,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=22).pack(side="left", padx=5)
        tk.Button(row1, text="⏱️ Ladegeschwindigkeit", command=self.page_speed,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), width=22).pack(side="left", padx=5)
        
        row2 = tk.Frame(btn_frame, bg="#1a1a1a")
        row2.pack(pady=5)
        
        tk.Button(row2, text="🤖 robots.txt", command=self.get_robots,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold"), width=22).pack(side="left", padx=5)
        tk.Button(row2, text="🗺️ sitemap.xml", command=self.get_sitemap_info,
                 bg="#00BCD4", fg="white", font=("Arial", 10, "bold"), width=22).pack(side="left", padx=5)
        
        row3 = tk.Frame(btn_frame, bg="#1a1a1a")
        row3.pack(pady=5)
        
        tk.Button(row3, text="🍪 Cookies anzeigen", command=self.show_cookies,
                 bg="#FF5722", fg="white", font=("Arial", 10, "bold"), width=22).pack(side="left", padx=5)
        
        self.tools_text = scrolledtext.ScrolledText(parent, height=20, bg="#2d2d2d", fg="#00ff00",
                                                     font=("Consolas", 9))
        self.tools_text.pack(fill="both", expand=True, padx=20, pady=10)
    
    def get_url(self):
        url = self.url_entry.get().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def analyze(self):
        threading.Thread(target=self.full_analysis, daemon=True).start()
    
    def full_analysis(self):
        url = self.get_url()
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(tk.END, f"Analysiere: {url}\n\n")
        
        result = self.tool.analyze_website(url)
        
        if 'error' in result:
            self.analysis_text.insert(tk.END, f"❌ Fehler: {result['error']}\n")
            return
        
        self.analysis_text.insert(tk.END, "=== WEBSITE-ANALYSE ===\n\n")
        self.analysis_text.insert(tk.END, f"Status Code: {result['status_code']}\n")
        self.analysis_text.insert(tk.END, f"Antwortzeit: {result['response_time']:.2f}s\n")
        self.analysis_text.insert(tk.END, f"Größe: {result['size']:,} Bytes\n")
        self.analysis_text.insert(tk.END, f"Titel: {result['title']}\n\n")
        self.analysis_text.insert(tk.END, f"Links: {result['links']}\n")
        self.analysis_text.insert(tk.END, f"Bilder: {result['images']}\n")
        self.analysis_text.insert(tk.END, f"Scripts: {result['scripts']}\n")
        self.analysis_text.insert(tk.END, f"Formulare: {result['forms']}\n\n")
        self.analysis_text.insert(tk.END, "=== HTTP HEADERS ===\n\n")
        for key, value in result['headers'].items():
            self.analysis_text.insert(tk.END, f"{key}: {value}\n")
    
    def check_tech(self):
        url = self.get_url()
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(tk.END, "Erkenne Technologien...\n\n")
        
        techs = self.tool.check_technologies(url)
        
        self.analysis_text.insert(tk.END, "=== VERWENDETE TECHNOLOGIEN ===\n\n")
        if techs:
            for tech in techs:
                self.analysis_text.insert(tk.END, f"✓ {tech}\n")
        else:
            self.analysis_text.insert(tk.END, "Keine Technologien erkannt\n")
    
    def extract_links(self):
        url = self.get_url()
        self.links_text.delete(1.0, tk.END)
        self.links_text.insert(tk.END, "Extrahiere Links...\n\n")
        
        links = self.tool.extract_links(url)
        
        self.links_text.insert(tk.END, f"=== GEFUNDENE LINKS ({len(links)}) ===\n\n")
        for i, link in enumerate(links, 1):
            self.links_text.insert(tk.END, f"[{i}] {link['text']}\n")
            self.links_text.insert(tk.END, f"    {link['url']}\n\n")
    
    def extract_images(self):
        url = self.get_url()
        self.links_text.delete(1.0, tk.END)
        self.links_text.insert(tk.END, "Extrahiere Bilder...\n\n")
        
        images = self.tool.extract_images(url)
        
        self.links_text.insert(tk.END, f"=== GEFUNDENE BILDER ({len(images)}) ===\n\n")
        for i, img in enumerate(images, 1):
            self.links_text.insert(tk.END, f"[{i}] Alt: {img['alt']}\n")
            self.links_text.insert(tk.END, f"    URL: {img['url']}\n\n")
    
    def check_security(self):
        url = self.get_url()
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(tk.END, "Prüfe Sicherheit...\n\n")
        
        result = self.tool.check_security(url)
        
        if 'error' in result:
            self.security_text.insert(tk.END, f"❌ Fehler: {result['error']}\n")
            return
        
        self.security_text.insert(tk.END, "=== SICHERHEITS-ANALYSE ===\n\n")
        self.security_text.insert(tk.END, f"HTTPS: {'✓ Ja' if result['https'] else '✗ Nein'}\n\n")
        
        if result['ssl_info']:
            self.security_text.insert(tk.END, "=== SSL ZERTIFIKAT ===\n\n")
            ssl = result['ssl_info']
            self.security_text.insert(tk.END, f"Aussteller: {ssl.get('issuer', {}).get('organizationName', 'Unbekannt')}\n")
            self.security_text.insert(tk.END, f"Gültig von: {ssl.get('valid_from', 'Unbekannt')}\n")
            self.security_text.insert(tk.END, f"Gültig bis: {ssl.get('valid_until', 'Unbekannt')}\n\n")
        
        self.security_text.insert(tk.END, "=== SICHERHEITS-HEADER ===\n\n")
        for header, value in result['security_headers'].items():
            self.security_text.insert(tk.END, f"{header}:\n  {value}\n\n")
    
    def get_whois(self):
        url = self.get_url()
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(tk.END, "Hole WHOIS Informationen...\n\n")
        
        result = self.tool.get_whois_info(url)
        
        if 'error' in result:
            self.security_text.insert(tk.END, f"❌ Fehler: {result['error']}\n")
            return
        
        self.security_text.insert(tk.END, "=== WHOIS INFORMATIONEN ===\n\n")
        for key, value in result.items():
            self.security_text.insert(tk.END, f"{key}: {value}\n")
    
    def find_emails(self):
        url = self.get_url()
        self.extract_text.delete(1.0, tk.END)
        self.extract_text.insert(tk.END, "Suche E-Mail-Adressen...\n\n")
        
        emails = self.tool.find_emails(url)
        
        self.extract_text.insert(tk.END, f"=== GEFUNDENE E-MAILS ({len(emails)}) ===\n\n")
        for email in emails:
            self.extract_text.insert(tk.END, f"📧 {email}\n")
    
    def find_phones(self):
        url = self.get_url()
        self.extract_text.delete(1.0, tk.END)
        self.extract_text.insert(tk.END, "Suche Telefonnummern...\n\n")
        
        phones = self.tool.find_phone_numbers(url)
        
        self.extract_text.insert(tk.END, f"=== GEFUNDENE TELEFONNUMMERN ({len(phones)}) ===\n\n")
        for phone in phones:
            self.extract_text.insert(tk.END, f"📞 {phone}\n")
    
    def get_meta(self):
        url = self.get_url()
        self.extract_text.delete(1.0, tk.END)
        self.extract_text.insert(tk.END, "Extrahiere Meta-Tags...\n\n")
        
        meta = self.tool.get_meta_tags(url)
        
        self.extract_text.insert(tk.END, f"=== META-TAGS ({len(meta)}) ===\n\n")
        for name, content in meta.items():
            self.extract_text.insert(tk.END, f"{name}:\n  {content}\n\n")
    
    def seo_analysis(self):
        url = self.get_url()
        self.seo_text.delete(1.0, tk.END)
        self.seo_text.insert(tk.END, "Führe SEO-Analyse durch...\n\n")
        
        seo = self.tool.get_seo_analysis(url)
        
        self.seo_text.insert(tk.END, "=== SEO ANALYSE ===\n\n")
        self.seo_text.insert(tk.END, f"Title: {seo.get('title', 'N/A')}\n")
        self.seo_text.insert(tk.END, f"Title Länge: {seo.get('title_length', 0)} Zeichen {'(✓ OK)' if 30 <= seo.get('title_length', 0) <= 60 else '(⚠ Optimieren)'}\n\n")
        self.seo_text.insert(tk.END, f"Description: {seo.get('description', 'N/A')[:100]}...\n")
        self.seo_text.insert(tk.END, f"Description Länge: {seo.get('description_length', 0)} Zeichen {'(✓ OK)' if 120 <= seo.get('description_length', 0) <= 160 else '(⚠ Optimieren)'}\n\n")
        self.seo_text.insert(tk.END, f"H1 Tags: {seo.get('h1_count', 0)} {'(✓ OK)' if seo.get('h1_count', 0) == 1 else '(⚠ Sollte genau 1 sein)'}\n")
        self.seo_text.insert(tk.END, f"H2 Tags: {seo.get('h2_count', 0)}\n\n")
        self.seo_text.insert(tk.END, f"Bilder gesamt: {seo.get('images_total', 0)}\n")
        self.seo_text.insert(tk.END, f"Bilder ohne Alt: {seo.get('images_without_alt', 0)} {'(✓ OK)' if seo.get('images_without_alt', 0) == 0 else '(⚠ Alt-Tags hinzufügen)'}\n\n")
        self.seo_text.insert(tk.END, f"Canonical URL: {seo.get('canonical', 'N/A')}\n")
    
    def check_broken(self):
        url = self.get_url()
        self.seo_text.delete(1.0, tk.END)
        self.seo_text.insert(tk.END, "Prüfe Links (max. 50)...\n\n")
        
        broken = self.tool.check_broken_links(url)
        
        self.seo_text.insert(tk.END, f"=== DEFEKTE LINKS ({len(broken)}) ===\n\n")
        if broken:
            for link in broken:
                self.seo_text.insert(tk.END, f"❌ Status {link['status']}: {link['url']}\n")
        else:
            self.seo_text.insert(tk.END, "✓ Keine defekten Links gefunden!\n")
    
    def find_social(self):
        url = self.get_url()
        self.seo_text.delete(1.0, tk.END)
        self.seo_text.insert(tk.END, "Suche Social Media Links...\n\n")
        
        social = self.tool.get_social_media_links(url)
        
        self.seo_text.insert(tk.END, "=== SOCIAL MEDIA LINKS ===\n\n")
        if social:
            for platform, link in social.items():
                self.seo_text.insert(tk.END, f"{platform.upper()}: {link}\n")
        else:
            self.seo_text.insert(tk.END, "Keine Social Media Links gefunden\n")
    
    def page_speed(self):
        url = self.get_url()
        self.tools_text.delete(1.0, tk.END)
        self.tools_text.insert(tk.END, "Messe Ladegeschwindigkeit (3 Tests)...\n\n")
        
        speed = self.tool.get_page_speed(url)
        
        if speed:
            self.tools_text.insert(tk.END, "=== LADEGESCHWINDIGKEIT ===\n\n")
            self.tools_text.insert(tk.END, f"Schnellste: {speed['min']:.3f}s\n")
            self.tools_text.insert(tk.END, f"Langsamste: {speed['max']:.3f}s\n")
            self.tools_text.insert(tk.END, f"Durchschnitt: {speed['avg']:.3f}s\n\n")
            
            if speed['avg'] < 1:
                self.tools_text.insert(tk.END, "✓ Sehr schnell!\n")
            elif speed['avg'] < 3:
                self.tools_text.insert(tk.END, "⚠ Akzeptabel\n")
            else:
                self.tools_text.insert(tk.END, "❌ Langsam - Optimierung empfohlen\n")
    
    def get_robots(self):
        url = self.get_url()
        self.tools_text.delete(1.0, tk.END)
        self.tools_text.insert(tk.END, "Lade robots.txt...\n\n")
        
        robots = self.tool.get_robots_txt(url)
        self.tools_text.insert(tk.END, "=== ROBOTS.TXT ===\n\n")
        self.tools_text.insert(tk.END, robots)
    
    def get_sitemap_info(self):
        url = self.get_url()
        self.tools_text.delete(1.0, tk.END)
        self.tools_text.insert(tk.END, "Lade sitemap.xml...\n\n")
        
        sitemap = self.tool.get_sitemap(url)
        self.tools_text.insert(tk.END, "=== SITEMAP.XML ===\n\n")
        self.tools_text.insert(tk.END, sitemap)
    
    def show_cookies(self):
        url = self.get_url()
        self.tools_text.delete(1.0, tk.END)
        self.tools_text.insert(tk.END, "Sammle Cookies...\n\n")
        
        cookies = self.tool.get_cookies(url)
        
        self.tools_text.insert(tk.END, f"=== COOKIES ({len(cookies)}) ===\n\n")
        for cookie in cookies:
            self.tools_text.insert(tk.END, f"Name: {cookie['name']}\n")
            self.tools_text.insert(tk.END, f"Wert: {cookie['value']}...\n")
            self.tools_text.insert(tk.END, f"Domain: {cookie['domain']}\n")
            self.tools_text.insert(tk.END, f"Path: {cookie['path']}\n\n")
    
    def download_site(self):
        url = self.get_url()
        save_path = filedialog.asksaveasfilename(defaultextension=".html",
                                                  filetypes=[("HTML", "*.html"), ("All", "*.*")])
        if save_path:
            if self.tool.download_website(url, save_path):
                messagebox.showinfo("Erfolg", f"Website gespeichert:\n{save_path}")
            else:
                messagebox.showerror("Fehler", "Download fehlgeschlagen!")

if __name__ == "__main__":
    WebsiteToolGUI()
