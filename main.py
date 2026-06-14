import sys
import time
import math
import ctypes
from ctypes import wintypes
import http.server
import socketserver
import threading
import json

# --- Windows Hafıza Okuma API Yapılandırması (Sıfır Bağımlılık) ---
kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HANDLE), ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)
    ]

def get_process_id(process_name):
    TH32CS_SNAPPROCESS = 0x00000002
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if kernel32.Process32First(snapshot, ctypes.byref(pe)):
        while kernel32.Process32Next(snapshot, ctypes.byref(pe)):
            if pe.szExeFile.decode('utf-8').lower() == process_name.lower():
                kernel32.CloseHandle(snapshot)
                return pe.th32ProcessID
    kernel32.CloseHandle(snapshot)
    return None

def get_module_base(pid, module_name):
    TH32CS_SNAPMODULE = 0x00000008
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    if kernel32.Module32First(snapshot, ctypes.byref(me)):
        while kernel32.Module32Next(snapshot, ctypes.byref(me)):
            if me.szModule.decode('utf-8').lower() == module_name.lower():
                base_addr = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                kernel32.CloseHandle(snapshot)
                return base_addr
    kernel32.CloseHandle(snapshot)
    return None

def read_memory(handle, address, c_type):
    buffer = c_type()
    bytes_read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(c_type), ctypes.byref(bytes_read)):
        return buffer.value
    return 0

def read_vec3(handle, address):
    class Vec3(ctypes.Structure):
        _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("z", ctypes.c_float)]
    buffer = Vec3()
    bytes_read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(Vec3), ctypes.byref(bytes_read)):
        return {"x": buffer.x, "y": buffer.y, "z": buffer.z}
    return {"x": 0, "y": 0, "z": 0}

# --- 2026 Güncel Ofset Yapılandırması ---
class Offsets: 
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          
    dwCSGOInput = 0x2356240        

class Entity:
    def __init__(self, handle, pawn):
        self.handle = handle
        self.pawn = pawn
    @property
    def team(self): return read_memory(self.handle, self.pawn + Offsets.m_iTeamNum, ctypes.c_int)
    @property
    def health(self): return read_memory(self.handle, self.pawn + Offsets.m_iHealth, ctypes.c_int)
    @property
    def position(self): return read_vec3(self.handle, self.pawn + Offsets.m_vOldOrigin)

# Sunucu ve hafıza motoru arasındaki küresel veri köprüsü
radar_data = {"yaw": 0, "enemies": []}

class RadarWebHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): return # HTTP istek logları terminali kirletmesin diye kapatıldı
    
    def do_GET(self):
        if self.path == '/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(radar_data).encode('utf-8'))
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_RADAR_UI.encode('utf-8'))
        else:
            self.send_error(404)

def run_web_server():
    PORT = 8000
    with socketserver.TCPServer(("0.0.0.0", PORT), RadarWebHandler) as httpd:
        print(f"[+] Web Radar Arayuzu Baslatildi: http://localhost:{PORT}")
        httpd.serve_forever()

# --- MODERN HTML5 CANVAS RADAR ARAYÜZÜ ---
HTML_RADAR_UI = """
<!DOCTYPE html>
<html>
<head>
    <title>CS2 Web Radar</title>
    <style>
        body { margin: 0; background: #11141a; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; overflow: hidden; }
        #radarContainer { position: relative; }
        canvas { background: #161a22; border-radius: 50%; border: 4px solid #242b35; box-shadow: 0 0 20px rgba(0,0,0,0.6); }
        .info { position: absolute; top: -30px; left: 10px; color: #8a96a3; font-size: 14px; font-weight: bold; }
    </style>
</head>
<body>
    <div id="radarContainer">
        <div class="info">CS2 WEB RADAR // LOCALHOST</div>
        <canvas id="radar" width="600" height="600"></canvas>
    </div>
    <script>
        const canvas = document.getElementById('radar');
        const ctx = canvas.getContext('2d');
        const center = canvas.width / 2;
        const SCALE = 0.18; // Radar harita ölçeği / yakınlaştırma derecesi

        function drawRadarGrid() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Radar İç Halkaları
            ctx.strokeStyle = '#242b35';
            ctx.lineWidth = 1;
            for(let r = 100; r <= center; r += 100) {
                ctx.beginPath();
                ctx.arc(center, center, r, 0, 2 * Math.PI);
                ctx.stroke();
            }

            // Radar Çapraz Eksen Çizgileri
            ctx.beginPath();
            ctx.moveTo(center, 0); ctx.lineTo(center, canvas.height);
            ctx.moveTo(0, center); ctx.lineTo(canvas.width, center);
            ctx.stroke();

            // Merkezdeki Oyuncu Simgesi (Sen)
            ctx.fillStyle = '#00ffcc';
            ctx.beginPath();
            ctx.moveTo(center, center - 8);
            ctx.lineTo(center - 6, center + 6);
            ctx.lineTo(center + 6, center + 6);
            ctx.closePath();
            ctx.fill();
        }

        async function updateRadar() {
            try {
                const response = await fetch('/data');
                const data = await response.json();
                
                drawRadarGrid();
                
                const yawRad = (data.yaw * Math.PI) / 180;

                data.enemies.forEach(enemy => {
                    let dx = enemy.x;
                    let dy = enemy.y;

                    // Oyuncunun bakış açısına (Yaw) göre 2D Rotasyon Matrisi dönüşümü
                    let rx = dx * Math.cos(-yawRad) - dy * Math.sin(-yawRad);
                    let ry = dx * Math.sin(-yawRad) + dy * Math.cos(-yawRad);

                    // Ekrana yerleşim piksel hesabı
                    let screenX = center + (rx * SCALE);
                    let screenY = center - (ry * SCALE);

                    // Sınır kırpma kontrolü (Düşmanın radardan taşmasını önler)
                    let distFromCenter = Math.sqrt(Math.pow(screenX - center, 2) + Math.pow(screenY - center, 2));
                    if (distFromCenter < center - 10) {
                        // Can değerine göre dinamik renk değişimi (Yeşil -> Kırmızı)
                        ctx.fillStyle = `rgb(255, ${Math.floor(enemy.health * 2.55)}, 0)`;
                        ctx.beginPath();
                        ctx.arc(screenX, screenY, 6, 0, 2 * Math.PI);
                        ctx.fill();
                        ctx.strokeStyle = '#fff';
                        ctx.lineWidth = 1;
                        ctx.stroke();
                    }
                });
            } catch (e) { }
            setTimeout(updateRadar, 30); // Akıcı yenileme hızı (~33 FPS)
        }
        updateRadar();
    </script>
</body>
</html>
"""

def main():
    global radar_data
    pid = None
    while pid is None:
        pid = get_process_id("cs2.exe")
        if pid is None:
            sys.stdout.write("\r[ Waiting ] cs2.exe bekleniyor... Lutfen oyunu acin. \x1b[K")
            sys.stdout.flush()
            time.sleep(1)

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    base = get_module_base(pid, "client.dll")

    # Web sunucusunu ana döngüden ayırmak (Thread) için arka planda tetikliyoruz
    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()

    print("[+] Hafiza motoru aktif hale getirildi. Veriler web sunucusuna aktariliyor.")

    while True:
        try:
            EntityList = read_memory(handle, base + Offsets.dwEntityList, ctypes.c_uint64)
            localPlayerPawnAddr = read_memory(handle, base + Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            csgoInput = read_memory(handle, base + Offsets.dwCSGOInput, ctypes.c_uint64)
            
            if not localPlayerPawnAddr or not csgoInput:
                time.sleep(0.1)
                continue
                
            localPlayer = Entity(handle, localPlayerPawnAddr)
            local_pos = localPlayer.position
            view_angles_y = read_memory(handle, csgoInput + 0x44, ctypes.c_float)

            temp_enemies = []

            for i in range(1, 64):
                listEntry = read_memory(handle, EntityList + (8 * (i & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                if listEntry == 0: continue   
                entity = read_memory(handle, listEntry + 112 * (i & 0x1FF), ctypes.c_uint64)
                if entity == 0: continue                          
                entityCPawn = read_memory(handle, entity + Offsets.m_hPlayerPawn, ctypes.c_uint)
                if entityCPawn == 0: continue   
                listEntry2  = read_memory(handle, EntityList + 0x8 * ((entityCPawn & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                if listEntry2 == 0: continue 
                entityPawn = read_memory(handle, listEntry2 + 112 * (entityCPawn & 0x1FF), ctypes.c_uint64)
                if entityPawn == 0: continue 

                player = Entity(handle, entityPawn)

                if localPlayer.team != player.team and player.health > 0:
                    player_pos = player.position
                    if player_pos["x"] == 0 and player_pos["y"] == 0: continue

                    # Sözdizimi hatası düzeldi: doğrudan can verisi aktarılıyor
                    temp_enemies.append({
                        "x": player_pos["x"] - local_pos["x"],
                        "y": player_pos["y"] - local_pos["y"],
                        "health": player.health
                    })

            # Küresel verileri güvenli ve stabil olarak güncelle
            radar_data = {
                "yaw": view_angles_y,
                "enemies": temp_enemies
            }
            
            time.sleep(0.015) # 60Hz tarama frekansı
                
        except Exception:
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    main()
                
