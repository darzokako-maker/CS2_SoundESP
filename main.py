import sys
import time
import math
import ctypes
from ctypes import wintypes
import http.server
import socketserver
import threading
import json
import os

# --- Windows Hafıza Okuma API Yapılandırması ---
kernel32 = ctypes.windll.kernel32

kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", wintypes.HANDLE), ("UniqueThread", wintypes.HANDLE)]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE), ("ObjectName", ctypes.c_void_p),
        ("Attributes", wintypes.ULONG), ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)), ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HANDLE), ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)
    ]

def _get_ntdll_syscall_address():
    h_ntdll = kernel32.GetModuleHandleW("ntdll.dll")
    nt_read_addr = kernel32.GetProcAddress(h_ntdll, b"NtReadVirtualMemory")
    if not nt_read_addr: return 0
    for offset in range(0, 100):
        ptr = nt_read_addr + offset
        if ctypes.string_at(ptr, 2) == b"\x0F\x05": return ptr
    return nt_read_addr + 0x12

_LEGAL_SYSCALL_ADDR = _get_ntdll_syscall_address()
_op_shellcode = b"\x4C\x8B\xD1\xB8\x26\x00\x00\x00\x49\xBB" + ctypes.c_uint64(_LEGAL_SYSCALL_ADDR).value.to_bytes(8, 'little') + b"\x41\xFF\xE3\xC3"
_rvm_shellcode = b"\x4C\x8B\xD1\xB8\x3F\x00\x00\x00\x49\xBB" + ctypes.c_uint64(_LEGAL_SYSCALL_ADDR).value.to_bytes(8, 'little') + b"\x41\xFF\xE3\xC3"

buf_op = kernel32.VirtualAlloc(None, len(_op_shellcode), 0x1000 | 0x2000, 0x40)
ctypes.memmove(buf_op, _op_shellcode, len(_op_shellcode))
_IndirectNtOpenProcess = ctypes.WINFUNCTYPE(wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.POINTER(OBJECT_ATTRIBUTES), ctypes.POINTER(CLIENT_ID))(buf_op)

buf_rvm = kernel32.VirtualAlloc(None, len(_rvm_shellcode), 0x1000 | 0x2000, 0x40)
ctypes.memmove(buf_rvm, _rvm_shellcode, len(_rvm_shellcode))
_IndirectNtReadVirtualMemory = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))(buf_rvm)

def indirect_open_process(pid):
    handle = wintypes.HANDLE()
    client_id = CLIENT_ID(ctypes.c_void_p(pid), None)
    obj_attr = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), None, None, 0, None, None)
    if _IndirectNtOpenProcess(ctypes.byref(handle), 0x0010 | 0x0400, ctypes.byref(obj_attr), ctypes.byref(client_id)) == 0:
        return handle.value
    return None

def get_process_id(process_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    if kernel32.Process32First(snapshot, ctypes.byref(pe)):
        while kernel32.Process32Next(snapshot, ctypes.byref(pe)):
            if pe.szExeFile.decode('utf-8', errors='ignore').lower() == process_name.lower():
                kernel32.CloseHandle(snapshot)
                return pe.th32ProcessID
    kernel32.CloseHandle(snapshot)
    return None

def get_module_base(pid, module_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    kernel32.Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    kernel32.Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    if kernel32.Module32First(snapshot, ctypes.byref(me)):
        while kernel32.Module32Next(snapshot, ctypes.byref(me)):
            if me.szModule.decode('utf-8', errors='ignore').lower() == module_name.lower():
                base_addr = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                kernel32.CloseHandle(snapshot)
                return base_addr
    kernel32.CloseHandle(snapshot)
    return None

def read_memory(handle, address, c_type):
    buffer = c_type()
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(c_type), ctypes.byref(bytes_read)) == 0:
        return buffer.value
    return 0

def read_string(handle, address, max_len=64):
    buffer = ctypes.create_string_buffer(max_len)
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), max_len, ctypes.byref(bytes_read)) == 0:
        try:
            return buffer.value.decode('utf-8', errors='ignore').split('\x00')[0].strip()
        except:
            return "de_mirage"
    return "de_mirage"

def read_vec3(handle, address):
    class Vec3(ctypes.Structure):
        _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("z", ctypes.c_float)]
    buffer = Vec3()
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(Vec3), ctypes.byref(bytes_read)) == 0:
        return {"x": buffer.x, "y": buffer.y, "z": buffer.z}
    return {"x": 0, "y": 0, "z": 0}

def get_asset_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- CS2 Ofset Yapısı ---
class Offsets:
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  
    dwCSGOInput = 0x2356240        
    dwGlobalVars = 0x17CD0F0       
    dwMatchmakingGameDLL = 0x33A380 
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          
    m_iszPlayerName = 0x638        
    m_pInGameMoneyServices = 0x6F8 
    m_iAccount = 0x40              
    m_angEyeAngles = 0x139C        

class Entity:
    def __init__(self, handle, controller, pawn):
        self.handle = handle
        self.controller = controller
        self.pawn = pawn
    
    @property
    def team(self): return read_memory(self.handle, self.pawn + Offsets.m_iTeamNum, ctypes.c_int)
    @property
    def health(self): return read_memory(self.handle, self.pawn + Offsets.m_iHealth, ctypes.c_int)
    @property
    def position(self): return read_vec3(self.handle, self.pawn + Offsets.m_vOldOrigin)
    
    @property
    def name(self):
        if not self.controller: return "LocalPlayer"
        name_ptr = read_memory(self.handle, self.controller + Offsets.m_iszPlayerName, ctypes.c_uint64)
        if name_ptr: return read_string(self.handle, name_ptr, 32)
        return "Player"
        
    @property
    def money(self):
        if not self.controller: return 0
        money_services = read_memory(self.handle, self.controller + Offsets.m_pInGameMoneyServices, ctypes.c_uint64)
        if not money_services: return 0
        return read_memory(self.handle, money_services + Offsets.m_iAccount, ctypes.c_int)

radar_data = {"map_name": "de_mirage", "yaw": 0, "local_team": 0, "players": []}

class RadarWebHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): return
    def do_GET(self):
        if self.path.startswith('/data'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(radar_data).encode('utf-8'))
        elif self.path in ['/de_dust2.png', '/de_mirage.png', '/de_inferno.png', '/de_nuke.png']:
            filename = self.path[1:]
            full_path = get_asset_path(filename)
            if os.path.exists(full_path):
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.end_headers()
                with open(full_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)
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
        httpd.serve_forever()

# --- DUST 2 VE NUKE KALİBRASYONLU GÜNCEL UI ---
HTML_RADAR_UI = """
<!DOCTYPE html>
<html>
<head>
    <title>CS2 Radar Engine Pro</title>
    <style>
        body { margin: 0; background: #0b0e14; display: flex; color: #fff; font-family: 'Segoe UI', sans-serif; height: 100vh; overflow: hidden; }
        .panel { display: flex; flex-direction: column; height: 100%; box-sizing: border-box; padding: 20px; background: #11141c; border-right: 2px solid #1c212e; }
        .team-panel { width: 25%; overflow-y: auto; }
        .team-title { font-size: 16px; font-weight: bold; padding-bottom: 10px; margin-bottom: 15px; border-bottom: 2px solid; text-align: center; }
        .team-my { color: #00ffcc; border-color: #00ffcc; }
        .team-enemy { color: #ff4444; border-color: #ff4444; }
        .player-card { background: #171c26; border-radius: 6px; padding: 10px; margin-bottom: 8px; border-left: 5px solid #8a96a3; }
        .player-card.alive { border-left-color: #44ff44; }
        .player-card.dead { border-left-color: #ff4444; opacity: 0.4; }
        .player-row { display: flex; justify-content: space-between; align-items: center; }
        .player-name { font-weight: bold; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .player-money { color: #2ecc71; font-weight: bold; font-family: monospace; }
        .hp-bar-bg { width: 100%; background: #222; height: 5px; border-radius: 2px; margin-top: 5px; overflow: hidden; }
        .hp-bar-fill { height: 100%; transition: width 0.1s; }
        
        .center-panel { width: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; background: #0d1017; position: relative; }
        .map-selector { display: flex; gap: 10px; margin-bottom: 15px; z-index: 10; }
        .map-btn { background: #1c212e; color: #8a96a3; border: 2px solid #242b35; padding: 8px 16px; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.2s; }
        .map-btn:hover { background: #242b35; color: #fff; }
        .map-btn.active { background: #00ffcc; color: #0b0e14; border-color: #00ffcc; box-shadow: 0 0 10px rgba(0,255,204,0.4); }

        #radar-container { position: relative; width: 620px; height: 620px; box-shadow: 0 0 30px rgba(0,0,0,0.8); border: 3px solid #242b35; border-radius: 4px; overflow: hidden; background: #000; }
        canvas { position: absolute; top: 0; left: 0; z-index: 2; }
        #map-bg { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; background-size: 100% 100%; background-repeat: no-repeat; background-position: center; }
    </style>
</head>
<body>
    <div class="panel team-panel">
        <div class="team-title team-my">MÜTTEFİKLER</div>
        <div id="myTeamList"></div>
    </div>
    <div class="panel center-panel">
        <div class="map-selector">
            <button class="map-btn" id="btn-de_dust2" onclick="selectMap('de_dust2')">DUST 2</button>
            <button class="map-btn" id="btn-de_mirage" onclick="selectMap('de_mirage')">MIRAGE</button>
            <button class="map-btn" id="btn-de_inferno" onclick="selectMap('de_inferno')">INFERNO</button>
            <button class="map-btn" id="btn-de_nuke" onclick="selectMap('de_nuke')">NUKE</button>
        </div>
        <div id="radar-container">
            <div id="map-bg"></div>
            <canvas id="radar" width="620" height="620"></canvas>
        </div>
    </div>
    <div class="panel team-panel" style="border-right: none;">
        <div class="team-title team-enemy">RAKİPLER</div>
        <div id="enemyTeamList"></div>
    </div>

    <script>
        const canvas = document.getElementById('radar');
        const ctx = canvas.getContext('2d');
        const mapBg = document.getElementById('map-bg');
        
        let manualMapSelection = null;

        // Yenilenmiş ve Hassas Ölçeklendirilmiş Harita Sınır Verileri (Milimetrik Ayarlı)
        const MAP_METADATA = {
            "de_dust2":   { pos_x: -2476, pos_y: 3239,  scale: 4.4,  offset_x: 0,   offset_y: 0 },
            "de_mirage":  { pos_x: -3230, pos_y: 1713,  scale: 5.0,  offset_x: 0,   offset_y: 0 },
            "de_inferno": { pos_x: -2087, pos_y: 3870,  scale: 4.9,  offset_x: 0,   offset_y: 0 },
            "de_nuke":    { pos_x: -3450, pos_y: -485,  scale: 7.0,  offset_x: -10, offset_y: -5 }
        };

        function selectMap(mapName) {
            manualMapSelection = mapName;
            updateMapVisuals(mapName);
        }

        function updateMapVisuals(mapName) {
            mapBg.style.backgroundImage = "url('/" + mapName + ".png')";
            document.querySelectorAll('.map-btn').forEach(btn => btn.classList.remove('active'));
            const activeBtn = document.getElementById('btn-' + mapName);
            if (activeBtn) activeBtn.classList.add('active');
        }

        function calculatePixelCoords(worldX, worldY, mapName) {
            const meta = MAP_METADATA[mapName] || MAP_METADATA["de_mirage"];
            
            // Dünya koordinatlarını radar ölçeğine (1024x1024 standart çözünürlüğe) dönüştürme
            let pixelX = (worldX - meta.pos_x) / meta.scale;
            let pixelY = (meta.pos_y - worldY) / meta.scale;
            
            // Tarayıcıdaki 620x620 piksel alanına tam oturtma ve harita spesifik kaymaları (offset) sıfırlama
            let finalX = (pixelX / 1024) * canvas.width + meta.offset_x;
            let finalY = (pixelY / 1024) * canvas.height + meta.offset_y;
            
            return { x: finalX, y: finalY };
        }

        function drawPlayer(x, y, yaw, isLocal, isTeammate, name, health) {
            const color = isLocal ? '#00ffcc' : (isTeammate ? '#3498db' : '#e74c3c');
            let lookRad = ((yaw - 90) * Math.PI) / 180;
            
            // Görüş Açısı Çizgisi
            ctx.strokeStyle = color;
            ctx.lineWidth = 3;
            ctx.lineCap = "round";
            ctx.beginPath();
            ctx.moveTo(x, y);
            ctx.lineTo(x + Math.cos(lookRad) * 14, y + Math.sin(lookRad) * 14);
            ctx.stroke();

            // Oyuncu Noktası
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(x, y, 7, 0, 2 * Math.PI);
            ctx.fill();
            
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            // Oyuncu İsmi
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 11px Segoe UI';
            ctx.textAlign = 'center';
            ctx.fillText(name, x, y - 12);
        }

        function createPlayerCard(player) {
            const statusClass = player.health > 0 ? 'alive' : 'dead';
            const hpColor = player.health < 35 ? '#e74c3c' : (player.health < 70 ? '#f1c40f' : '#2ecc71');
            return `
                <div class="player-card \${statusClass}">
                    <div class="player-row">
                        <span class="player-name">\${player.name}</span>
                        <span class="player-money">$\${player.money}</span>
                    </div>
                    <div class="hp-bar-bg">
                        <div class="hp-bar-fill" style="width: \${Math.max(0, player.health)}%; background-color: \-- hpColor};"></div>
                    </div>
                </div>
            `;
        }

        async function tick() {
            try {
                const response = await fetch('/data?t=' + new Date().getTime());
                const data = await response.json();
                
                let activeMap = manualMapSelection || data.map_name || "de_mirage";
                if (!MAP_METADATA[activeMap]) activeMap = "de_mirage";
                
                if (mapBg.style.backgroundImage.indexOf(activeMap) === -1) {
                    updateMapVisuals(activeMap);
                }

                ctx.clearRect(0, 0, canvas.width, canvas.height);

                let myTeamHTML = "";
                let enemyTeamHTML = "";
                
                data.players.forEach(p => {
                    if (p.team === data.local_team) myTeamHTML += createPlayerCard(p);
                    else enemyTeamHTML += createPlayerCard(p);

                    if (p.health > 0) {
                        let coords = calculatePixelCoords(p.world_x, p.world_y, activeMap);
                        // Eğer harita sınırları dışındaysa bile ekranda kırpılmasını engelle
                        if(coords.x >= 0 && coords.x <= canvas.width && coords.y >= 0 && coords.y <= canvas.height) {
                            drawPlayer(coords.x, coords.y, p.yaw, p.is_local, p.team === data.local_team, p.name, p.health);
                        }
                    }
                });

                document.getElementById('myTeamList').innerHTML = myTeamHTML;
                document.getElementById('enemyTeamList').innerHTML = enemyTeamHTML;

            } catch (e) {}
            setTimeout(tick, 10);
        }
        tick();
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
            sys.stdout.write("\r[ Waiting ] cs2.exe bekleniyor... \x1b[K")
            sys.stdout.flush()
            time.sleep(1)

    handle = indirect_open_process(pid)
    if not handle: return
    base = get_module_base(pid, "client.dll")

    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()

    print("[+] Gelişmiş Senkronizasyon Radarı Aktif: http://localhost:8000")

    while True:
        try:
            EntityList = read_memory(handle, base + Offsets.dwEntityList, ctypes.c_uint64)
            localPlayerPawnAddr = read_memory(handle, base + Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            csgoInput = read_memory(handle, base + Offsets.dwCSGOInput, ctypes.c_uint64)
            
            if not localPlayerPawnAddr or not csgoInput:
                time.sleep(0.1)
                continue
                
            localPlayer = Entity(handle, 0, localPlayerPawnAddr)
            local_team = localPlayer.team
            view_angles_y = read_memory(handle, csgoInput + 0x44, ctypes.c_float)

            map_name = "de_mirage"
            try:
                game_lib = get_module_base(pid, "matchmaking.dll")
                if game_lib:
                    map_ptr = read_memory(handle, game_lib + Offsets.dwMatchmakingGameDLL, ctypes.c_uint64)
                    if map_ptr:
                        raw_map = read_string(handle, map_ptr, 64)
                        map_aliases = ["de_dust2", "de_mirage", "de_inferno", "de_nuke"]
                        for m in map_aliases:
                            if m in raw_map:
                                map_name = m
                                break
            except:
                map_name = "de_mirage"

            temp_players = []

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

                player = Entity(handle, entity, entityPawn)
                player_pos = player.position
                player_yaw = read_memory(handle, entityPawn + Offsets.m_angEyeAngles, ctypes.c_float)
                is_local = (entityPawn == localPlayerPawnAddr)

                temp_players.append({
                    "name": player.name,
                    "health": player.health,
                    "money": player.money,
                    "team": player.team,
                    "is_local": is_local,
                    "yaw": player_yaw,
                    "world_x": player_pos["x"],
                    "world_y": player_pos["y"]
                })

            radar_data = {
                "map_name": map_name,
                "yaw": view_angles_y,
                "local_team": local_team,
                "players": temp_players
            }
            
            time.sleep(0.01)
                
        except Exception:
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    main()
