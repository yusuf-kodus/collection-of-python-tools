import yt_dlp
import os
import json
from datetime import datetime

class YouTubeTool:
    def __init__(self):
        # Nutze User-Dokumente-Ordner statt System32
        user_docs = os.path.expanduser("~\\Documents")
        self.download_path = os.path.join(user_docs, "YouTube_Downloads")
        try:
            os.makedirs(self.download_path, exist_ok=True)
        except:
            # Fallback: Aktuelles Verzeichnis
            self.download_path = os.path.join(os.path.dirname(__file__), "downloads")
            os.makedirs(self.download_path, exist_ok=True)
    
    def search_videos(self, query, max_results=10):
        """Sucht nach Videos"""
        ydl_opts = {'quiet': True, 'no_warnings': True, 'extract_flat': True, 'ignoreerrors': True}
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                result = ydl.extract_info(f"ytsearch{max_results}:{query}", download=False)
                return result.get('entries', []) if result else []
        except Exception as e:
            print(f"Suchfehler: {e}")
            return []
    
    def get_video_info(self, url):
        """Holt detaillierte Video-Infos"""
        ydl_opts = {'quiet': True, 'no_warnings': True, 'ignoreerrors': True}
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                return ydl.extract_info(url, download=False)
        except Exception as e:
            print(f"Info-Fehler: {e}")
            return None
    
    def get_channel_info(self, channel_url):
        """Holt Channel-Informationen"""
        ydl_opts = {'quiet': True, 'no_warnings': True, 'extract_flat': True}
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                return ydl.extract_info(channel_url, download=False)
        except:
            return None
    
    def download_video(self, url, quality='best'):
        """Lädt Video herunter"""
        ydl_opts = {
            'format': quality,
            'outtmpl': os.path.join(self.download_path, '%(title)s.%(ext)s'),
            'progress_hooks': [self._progress_hook],
        }
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                print(f"\n[*] Lade Video herunter...")
                ydl.download([url])
                print(f"\n✓ Download abgeschlossen!")
                return True
        except Exception as e:
            print(f"\n✗ Fehler: {e}")
            return False
    
    def download_audio(self, url):
        """Lädt nur Audio herunter (MP3)"""
        ydl_opts = {
            'format': 'bestaudio/best',
            'outtmpl': os.path.join(self.download_path, '%(title)s.%(ext)s'),
            'postprocessors': [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }],
            'progress_hooks': [self._progress_hook],
        }
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                print(f"\n[*] Lade Audio herunter...")
                ydl.download([url])
                print(f"\n✓ Download abgeschlossen!")
                return True
        except Exception as e:
            print(f"\n✗ Fehler: {e}")
            return False
    
    def download_playlist(self, url):
        """Lädt komplette Playlist herunter"""
        ydl_opts = {
            'format': 'best',
            'outtmpl': os.path.join(self.download_path, '%(playlist)s/%(title)s.%(ext)s'),
            'progress_hooks': [self._progress_hook],
        }
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                print(f"\n[*] Lade Playlist herunter...")
                ydl.download([url])
                print(f"\n✓ Playlist-Download abgeschlossen!")
                return True
        except Exception as e:
            print(f"\n✗ Fehler: {e}")
            return False
    
    def download_subtitles(self, url):
        """Lädt Untertitel herunter"""
        ydl_opts = {
            'skip_download': True,
            'writesubtitles': True,
            'writeautomaticsub': True,
            'subtitleslangs': ['de', 'en'],
            'outtmpl': os.path.join(self.download_path, '%(title)s.%(ext)s'),
        }
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                print(f"\n[*] Lade Untertitel herunter...")
                ydl.download([url])
                print(f"\n✓ Untertitel heruntergeladen!")
                return True
        except Exception as e:
            print(f"\n✗ Fehler: {e}")
            return False
    
    def download_thumbnail(self, url):
        """Lädt Thumbnail herunter"""
        ydl_opts = {
            'skip_download': True,
            'writethumbnail': True,
            'outtmpl': os.path.join(self.download_path, '%(title)s.%(ext)s'),
        }
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                print(f"\n[*] Lade Thumbnail herunter...")
                ydl.download([url])
                print(f"\n✓ Thumbnail heruntergeladen!")
                return True
        except Exception as e:
            print(f"\n✗ Fehler: {e}")
            return False
    
    def get_trending(self, region='DE'):
        """Holt Trending Videos"""
        ydl_opts = {'quiet': True, 'no_warnings': True, 'extract_flat': True}
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                result = ydl.extract_info(f"https://www.youtube.com/feed/trending", download=False)
                return result.get('entries', [])[:20]
        except:
            return []
    
    def get_available_formats(self, url):
        """Zeigt verfügbare Qualitäten"""
        info = self.get_video_info(url)
        if info and 'formats' in info:
            formats = []
            for f in info['formats']:
                if f.get('vcodec') != 'none':
                    formats.append({
                        'format_id': f.get('format_id'),
                        'ext': f.get('ext'),
                        'resolution': f.get('resolution', 'audio only'),
                        'filesize': f.get('filesize', 0),
                        'fps': f.get('fps', 0)
                    })
            return formats
        return []
    
    def _progress_hook(self, d):
        """Progress-Anzeige"""
        if d['status'] == 'downloading':
            percent = d.get('_percent_str', '0%')
            speed = d.get('_speed_str', 'N/A')
            eta = d.get('_eta_str', 'N/A')
            print(f"\r  Progress: {percent} | Speed: {speed} | ETA: {eta}", end='')
        elif d['status'] == 'finished':
            print(f"\r  ✓ Download abgeschlossen, verarbeite...")

def format_views(views):
    """Formatiert View-Anzahl"""
    if not views:
        return "0"
    if views >= 1000000:
        return f"{views/1000000:.1f}M"
    elif views >= 1000:
        return f"{views/1000:.1f}K"
    return str(views)

def format_duration(seconds):
    """Formatiert Dauer"""
    if not seconds:
        return "N/A"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"

def main():
    print("=" * 60)
    print("🎥 YOUTUBE TOOL - ULTIMATE EDITION")
    print("=" * 60)
    
    tool = YouTubeTool()
    
    while True:
        print("\n" + "=" * 60)
        print("[MENU]")
        print("=" * 60)
        print("1. 🔍 Video suchen")
        print("2. 📊 Video-Infos anzeigen")
        print("3. 📥 Video herunterladen")
        print("4. 🎵 Audio herunterladen (MP3)")
        print("5. 📋 Playlist herunterladen")
        print("6. 💬 Untertitel herunterladen")
        print("7. 🖼️ Thumbnail herunterladen")
        print("8. 📺 Channel-Infos")
        print("9. 🔥 Trending Videos")
        print("10. 🎬 Verfügbare Qualitäten")
        print("11. 📁 Downloads-Ordner öffnen")
        print("0. Beenden")
        
        choice = input("\n> Wähle: ")
        
        if choice == "1":
            query = input("\n🔍 Suche: ")
            if query:
                print(f"\n[*] Suche nach '{query}'...")
                results = tool.search_videos(query, 10)
                if results:
                    print(f"\n📋 {len(results)} Ergebnisse:\n")
                    for i, video in enumerate(results, 1):
                        if not video:
                            continue
                        title = video.get('title', 'N/A')
                        channel = video.get('channel', 'N/A')
                        duration = format_duration(video.get('duration', 0))
                        views = format_views(video.get('view_count', 0))
                        vid_id = video.get('id', '')
                        url = f"https://youtube.com/watch?v={vid_id}" if vid_id else "N/A"
                        
                        print(f"{i:2}. {title}")
                        print(f"    👤 {channel} | ⏱️ {duration} | 👁️ {views}")
                        print(f"    🔗 {url}\n")
                else:
                    print("✗ Nichts gefunden")
        
        elif choice == "2":
            url = input("\n🔗 Video-URL: ")
            if url:
                print("\n[*] Lade Infos...")
                info = tool.get_video_info(url)
                if info:
                    print(f"\n{'=' * 60}")
                    print(f"📊 {info.get('title', 'N/A')}")
                    print(f"{'=' * 60}")
                    print(f"👤 Channel: {info.get('channel', 'N/A')}")
                    print(f"👁️ Views: {format_views(info.get('view_count', 0))}")
                    print(f"👍 Likes: {format_views(info.get('like_count', 0))}")
                    print(f"💬 Kommentare: {format_views(info.get('comment_count', 0))}")
                    print(f"⏱️ Dauer: {format_duration(info.get('duration', 0))}")
                    print(f"📅 Upload: {info.get('upload_date', 'N/A')}")
                    print(f"🎬 Qualität: {info.get('resolution', 'N/A')}")
                    print(f"\n📝 Beschreibung:")
                    desc = info.get('description', 'N/A')
                    print(f"{desc[:300]}..." if len(desc) > 300 else desc)
                else:
                    print("✗ Infos nicht verfügbar")
        
        elif choice == "3":
            url = input("\n🔗 Video-URL: ")
            if url:
                print("\n📋 Qualität wählen:")
                print("1. Best (höchste Qualität)")
                print("2. 1080p")
                print("3. 720p")
                print("4. 480p")
                print("5. 360p")
                
                q = input("\n> Wähle: ")
                quality_map = {
                    '1': 'best',
                    '2': 'bestvideo[height<=1080]+bestaudio/best',
                    '3': 'bestvideo[height<=720]+bestaudio/best',
                    '4': 'bestvideo[height<=480]+bestaudio/best',
                    '5': 'bestvideo[height<=360]+bestaudio/best'
                }
                quality = quality_map.get(q, 'best')
                tool.download_video(url, quality)
        
        elif choice == "4":
            url = input("\n🔗 Video-URL: ")
            if url:
                tool.download_audio(url)
        
        elif choice == "5":
            url = input("\n🔗 Playlist-URL: ")
            if url:
                tool.download_playlist(url)
        
        elif choice == "6":
            url = input("\n🔗 Video-URL: ")
            if url:
                tool.download_subtitles(url)
        
        elif choice == "7":
            url = input("\n🔗 Video-URL: ")
            if url:
                tool.download_thumbnail(url)
        
        elif choice == "8":
            url = input("\n🔗 Channel-URL: ")
            if url:
                print("\n[*] Lade Channel-Infos...")
                info = tool.get_channel_info(url)
                if info:
                    print(f"\n{'=' * 60}")
                    print(f"📺 {info.get('channel', 'N/A')}")
                    print(f"{'=' * 60}")
                    print(f"👥 Subscriber: {format_views(info.get('channel_follower_count', 0))}")
                    print(f"🎬 Videos: {info.get('playlist_count', 'N/A')}")
                    print(f"\n📝 Beschreibung:")
                    desc = info.get('description', 'N/A')
                    print(f"{desc[:300]}..." if len(desc) > 300 else desc)
                else:
                    print("✗ Channel nicht gefunden")
        
        elif choice == "9":
            print("\n[*] Lade Trending Videos...")
            videos = tool.get_trending()
            if videos:
                print(f"\n🔥 TRENDING:\n")
                for i, video in enumerate(videos[:15], 1):
                    title = video.get('title', 'N/A')
                    channel = video.get('channel', 'N/A')
                    print(f"{i:2}. {title}")
                    print(f"    👤 {channel}\n")
            else:
                print("✗ Keine Trending-Daten")
        
        elif choice == "10":
            url = input("\n🔗 Video-URL: ")
            if url:
                print("\n[*] Lade verfügbare Formate...")
                formats = tool.get_available_formats(url)
                if formats:
                    print(f"\n🎬 VERFÜGBARE QUALITÄTEN:\n")
                    for f in formats:
                        size = f['filesize'] / 1024 / 1024 if f['filesize'] else 0
                        size_str = f"{size:.1f} MB" if size > 0 else "N/A"
                        print(f"ID: {f['format_id']:5} | {f['resolution']:15} | {f['ext']:4} | {size_str:10} | {f['fps']} fps")
                else:
                    print("✗ Keine Formate gefunden")
        
        elif choice == "11":
            print(f"\n📁 Downloads-Ordner: {tool.download_path}")
            try:
                os.startfile(tool.download_path)
            except Exception as e:
                print(f"✗ Konnte Ordner nicht öffnen: {e}")
        
        elif choice == "0":
            print("\n[*] Beende...")
            break
        
        else:
            print("✗ Ungültige Option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Unterbrochen")
    except Exception as e:
        print(f"\n✗ Fehler: {e}")
    finally:
        input("\nDrücke ENTER...")
