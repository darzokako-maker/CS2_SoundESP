import sys
import time
import math
import ctypes
from ctypes import wintypes
import http.server
import socketserver
import threading
import json

# --- Windows Hafıza Okuma API Yapılandırması (Indirect Syscall) ---
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
    if not nt_read_addr:
        return 0
    for offset in range(0, 100):
        ptr = nt_read_addr + offset
        if ctypes.string_at(ptr, 2) == b"\x0F\x05":
            return ptr
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
    TH32CS_SNAPPROCESS = 0x00000002
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
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
    TH32CS_SNAPMODULE = 0x00000008
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
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

def read_string(handle, address, max_len=32):
    buffer = ctypes.create_string_buffer(max_len)
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), max_len, ctypes.byref(bytes_read)) == 0:
        try:
            return buffer.value.decode('utf-8', errors='ignore')
        except:
            return "Unknown"
    return "Unknown"

def read_vec3(handle, address):
    class Vec3(ctypes.Structure):
        _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("z", ctypes.c_float)]
    buffer = Vec3()
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(Vec3), ctypes.byref(bytes_read)) == 0:
        return {"x": buffer.x, "y": buffer.y, "z": buffer.z}
    return {"x": 0, "y": 0, "z": 0}

# --- 2026 Ofsetleri ---
class Offsets: 
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  
    dwCSGOInput = 0x2356240        
    
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          
    m_iszPlayerName = 0x638        
    m_pInGameMoneyServices = 0x6F8 
    m_iAccount = 0x40              
    m_angEyeAngles = 0x14F8        
    
    # Silah Okuma İçin Gerekli Olan Ofsetler
    m_pWeaponServices = 0x1100     
    m_hActiveWeapon = 0x58         
    m_pClippingWeaponData = 0x368  
    m_szName = 0xC10               

class Entity:
    def __init__(self, handle, controller, pawn, entity_list_base=0):
        self.handle = handle
        self.controller = controller
        self.pawn = pawn
        self.entity_list = entity_list_base
    
    @property
    def team(self): return read_memory(self.handle, self.pawn + Offsets.m_iTeamNum, ctypes.c_int)
    @property
    def health(self): return read_memory(self.handle, self.pawn + Offsets.m_iHealth, ctypes.c_int)
    @property
    def position(self): return read_vec3(self.handle, self.pawn + Offsets.m_vOldOrigin)
    @property
    def yaw(self): return read_memory(self.handle, self.pawn + Offsets.m_angEyeAngles + 4, ctypes.c_float)
    @property
    def name(self):
        if not self.controller: return "Player"
        return read_string(self.handle, self.controller + Offsets.m_iszPlayerName, 32)
    
    @property
    def money(self):
        if not self.pawn: return 0
        # Parayı Pawn üzerinden değil, Controller üzerinden okumak daha kararlıdır.
        money_services = read_memory(self.handle, self.controller + Offsets.m_pInGameMoneyServices, ctypes.c_uint64)
        if not money_services: return 0
        return read_memory(self.handle, money_services + Offsets.m_iAccount, ctypes.c_int)

    @property
    def weapon(self):
        if not self.pawn or not self.entity_list: return "None"
        wpn_services = read_memory(self.handle, self.pawn + Offsets.m_pWeaponServices, ctypes.c_uint64)
        if not wpn_services: return "None"
        active_wpn_handle = read_memory(self.handle, wpn_services + Offsets.m_hActiveWeapon, ctypes.c_uint32)
        if active_wpn_handle == 0xFFFFFFFF: return "Knife"
        
        # Handle değerinden Entity indeksini çözme
        wpn_idx = active_wpn_handle & 0x7FFF
        list_entry = read_memory(self.handle, self.entity_list + (8 * (wpn_idx >> 9)) + 16, ctypes.c_uint64)
        if not list_entry: return "Knife"
        wpn_entity = read_memory(self.handle, list_entry + 120 * (wpn_idx & 0x1FF), ctypes.c_uint64)
        if not wpn_entity: return "Knife"
        
        wpn_data = read_memory(self.handle, wpn_entity + Offsets.m_pClippingWeaponData, ctypes.c_uint64)
        if not wpn_data: return "Knife"
        wpn_name_ptr = read_memory(self.handle, wpn_data + Offsets.m_szName, ctypes.c_uint64)
        if not wpn_name_ptr: return "Knife"
        
        full_name = read_string(self.handle, wpn_name_ptr, 32)
        if "weapon_" in full_name:
            return full_name.replace("weapon_", "").upper()
        return full_name.upper()

radar_data = {"yaw": 0, "local_team": 0, "players": []}

class RadarWebHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): return
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
        print(f"[+] Multi-Panel Web Arayuzu Baslatildi: http://localhost:{PORT}")
        httpd.serve_forever()

# --- GELİŞTİRİLMİŞ PANEL ARAYÜZÜ (SİLAH VE PARA DESTEKLİ) ---
HTML_RADAR_UI = """
<!DOCTYPE html>
<html>
<head>
    <title>CS2 Tactical Web Dashboard</title>
    <style>
        body { margin: 0; background: #0b0e14; display: flex; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; height: 100vh; overflow: hidden; }
        .panel { display: flex; flex-direction: column; height: 100%; box-sizing: border-box; padding: 20px; background: #11141c; border-right: 2px solid #1c212e; }
        .team-panel { width: 28%; overflow-y: auto; }
        .team-title { font-size: 18px; font-weight: bold; padding-bottom: 10px; margin-bottom: 15px; border-bottom: 2px solid; text-align: center; }
        .team-my { color: #00ffcc; border-color: #00ffcc; }
        .team-enemy { color: #ff4444; border-color: #ff4444; }
        .player-card { background: #171c26; border-radius: 6px; padding: 12px; margin-bottom: 10px; border-left: 5px solid #8a96a3; display: flex; flex-direction: column; gap: 6px; }
        .player-card.alive { border-left-color: #44ff44; }
        .player-card.dead { border-left-color: #ff4444; opacity: 0.4; }
        .player-row { display: flex; justify-content: space-between; align-items: center; }
        .player-name { font-weight: bold; max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .player-money { color: #2ecc71; font-weight: bold; font-family: monospace; font-size: 14px; }
        .player-weapon { color: #f39c12; font-size: 12px; font-weight: bold; font-family: monospace; }
        .hp-bar-bg { width: 100%; background: #222; height: 6px; border-radius: 3px; overflow: hidden; }
        .hp-bar-fill { height: 100%; background: #2ecc71; transition: width 0.1s; }
        .center-panel { width: 44%; display: flex; justify-content: center; align-items: center; position: relative; background: #0d1017; }
        canvas { background: #12161f; border-radius: 50%; border: 4px solid #242b35; box-shadow: 0 0 30px rgba(0,0,0,0.7); }
        .info-label { position: absolute; top: 20px; font-size: 14px; font-weight: bold; color: #526273; letter-spacing: 1px; }
    </style>
</head>
<body>
    <div class="panel team-panel">
        <div class="team-title team-my">MÜTTEFİKLER (MY TEAM)</div>
        <div id="myTeamList"></div>
    </div>
    <div class="panel center-panel">
        <div class="info-label">TACTICAL REALTIME RADAR</div>
        <canvas id="radar" width="520" height="520"></canvas>
    </div>
    <div class="panel team-panel" style="border-right: none;">
        <div class="team-title team-enemy">RAKİPLER (ENEMIES)</div>
        <div id="enemyTeamList"></div>
    </div>
    <script>
        const canvas = document.getElementById('radar');
        const ctx = canvas.getContext('2d');
        const center = canvas.width / 2;
        const SCALE = 0.16;

        function drawRadarGrid() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.strokeStyle = '#1f2533';
            ctx.lineWidth = 1;
            for(let r = 80; r <= center; r += 80) {
                ctx.beginPath(); ctx.arc(center, center, r, 0, 2 * Math.PI); ctx.stroke();
            }
            ctx.beginPath();
            ctx.moveTo(center, 0); ctx.lineTo(center, canvas.height);
            ctx.moveTo(0, center); ctx.lineTo(canvas.width, center);
            ctx.stroke();

            // Merkez Oyuncu Simgesi
            ctx.fillStyle = '#00ffcc';
            ctx.beginPath();
            ctx.moveTo(center, center - 13);
            ctx.lineTo(center - 8, center + 6);
            ctx.lineTo(center + 8, center + 6);
            ctx.closePath(); ctx.fill();
        }

        function createPlayerCard(player) {
            const statusClass = player.health > 0 ? 'alive' : 'dead';
            const hpWidth = Math.max(0, Math.min(100, player.health));
            let hpColor = '#2ecc71';
            if(player.health < 35) hpColor = '#e74c3c';
            else if(player.health < 70) hpColor = '#f1c40f';

            return `
                <div class="player-card ${statusClass}">
                    <div class="player-row">
                        <span class="player-name">${player.name}</span>
                        <span class="player-money">$${player.money}</span>
                    </div>
                    <div class="player-row" style="font-size: 11px; color: #a0aab5;">
                        <span>HP: ${player.health}</span>
                        <span class="player-weapon">${player.health > 0 ? player.weapon : 'DEAD'}</span>
                    </div>
                    <div class="hp-bar-bg">
                        <div class="hp-bar-fill" style="width: ${hpWidth}%; background-color: ${hpColor};"></div>
                    </div>
                </div>
            `;
        }

        async function updateDashboard() {
            try {
                const response = await fetch('/data');
                const data = await response.json();
                
                drawRadarGrid();
                const localYawRad = (data.yaw * Math.PI) / 180;

                let myTeamHTML = "";
                let enemyTeamHTML = "";

                data.players.forEach(p => {
                    if (p.team === data.local_team) {
                        myTeamHTML += createPlayerCard(p);
                    } else {
                        enemyTeamHTML += createPlayerCard(p);
                    }

                    if (p.health > 0 && !p.is_local) {
                        let rx = p.dx * Math.cos(-localYawRad) - p.dy * Math.sin(-localYawRad);
                        let ry = p.dx * Math.sin(-localYawRad) + p.dy * Math.cos(-localYawRad);

                        let screenX = center + (rx * SCALE);
                        let screenY = center - (ry * SCALE);

                        let dist = Math.sqrt(Math.pow(screenX - center, 2) + Math.pow(screenY - center, 2));
                        if (dist < center - 10) {
                            let relativeYaw = ((p.yaw - data.yaw) * Math.PI) / 180;
                            let color = p.team === data.local_team ? '#00ffcc' : '#ff4444';
                            
                            // 1. Oyuncu Yön Çizgisi
                            ctx.strokeStyle = color;
                            ctx.lineWidth = 2.5;
                            ctx.beginPath();
                            ctx.moveTo(screenX, screenY);
                            let lineLength = 15;
                            ctx.lineTo(screenX + Math.sin(relativeYaw) * lineLength, screenY - Math.cos(relativeYaw) * lineLength);
                            ctx.stroke();

                            // 2. Oyuncu Noktası
                            ctx.fillStyle = color;
                            ctx.beginPath(); 
                            ctx.arc(screenX, screenY, 6, 0, 2 * Math.PI); 
                            ctx.fill();
                            ctx.strokeStyle = '#ffffff'; 
                            ctx.lineWidth = 1.5; 
                            ctx.stroke();
                        }
                    }
                });

                document.getElementById('myTeamList').innerHTML = myTeamHTML;
                document.getElementById('enemyTeamList').innerHTML = enemyTeamHTML;

            } catch (e) { }
            setTimeout(updateDashboard, 30);
        }
        updateDashboard();
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
    if not handle:
        print("\n[-] Süreç baglantisi (Handle) alinmadi.")
        return
        
    base = get_module_base(pid, "client.dll")

    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()

    print("[+] Taktiksel Veri Hafıza Motoru Çalısıyor... (Indirect Syscall)")

    while True:
        try:
            EntityList = read_memory(handle, base + Offsets.dwEntityList, ctypes.c_uint64)
            localPlayerPawnAddr = read_memory(handle, base + Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            csgoInput = read_memory(handle, base + Offsets.dwCSGOInput, ctypes.c_uint64)
            
            if not localPlayerPawnAddr or not csgoInput:
                time.sleep(0.1)
                continue
                
            localPlayer = Entity(handle, 0, localPlayerPawnAddr)
            local_pos = localPlayer.position
            local_team = localPlayer.team
            view_angles_y = read_memory(handle, csgoInput + 0x44, ctypes.c_float)

            temp_players = []

            for i in range(1, 64):
                listEntry = read_memory(handle, EntityList + (8 * (i & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                if listEntry == 0: continue   
                entity = read_memory(handle, listEntry + 112 * (i & 0x1FF), ctypes.c_uint64)
                if entity == 0: continue                          
                entityCPawn = read_memory(handle, 
