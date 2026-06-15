import sys
import time
import math
import ctypes
from ctypes import wintypes
import http.server
import socketserver
import threading
import json
import random

# ==========================================
# C-STRUCTS (GLOBAL & X64 HİZALANMIŞ DURUMDA)
# ==========================================
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

# ==========================================
# KERNEL32 API PROTOTİPLERİ (64-BIT RESTYPE TANIMLAMALARI)
# ==========================================
_k32 = ctypes.windll.kernel32

_k32.VirtualAlloc.restype = ctypes.c_void_p
_k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

_k32.GetModuleHandleW.restype = wintypes.HMODULE
_k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

_k32.Process32First.restype = wintypes.BOOL
_k32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

_k32.Process32Next.restype = wintypes.BOOL
_k32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

_k32.Module32First.restype = wintypes.BOOL
_k32.Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]

_k32.Module32Next.restype = wintypes.BOOL
_k32.Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]

_PAGE_ERW = 0x40

def _0x3e1a_junk():
    _var_x = random.randint(5, 20)
    _temp = [((i ^ 0x3C) * 2) for i in range(_var_x)]
    if len(_temp) > 9999: pass

# --- NTDLL TAYİNİ & MEŞRU SYSCALL ADRESİ BULUCU (KIRPILMAZ) ---
def _get_ntdll_syscall_address():
    h_ntdll = _k32.GetModuleHandleW("ntdll.dll")
    nt_read_addr = _k32.GetProcAddress(h_ntdll, b"NtReadVirtualMemory")
    
    if not nt_read_addr:
        return 0
        
    for offset in range(0, 100):
        ptr = nt_read_addr + offset
        if ctypes.string_at(ptr, 2) == b"\x0F\x05":
            return ptr
    return nt_read_addr + 0x12

_LEGAL_SYSCALL_ADDR = _get_ntdll_syscall_address()

# ==========================================
# INDIRECT SYSCALL ASSEMBLY BRIDGES (x64 GÜVENLİ)
# ==========================================
_op_shellcode = (
    b"\x4C\x8B\xD1" +
    b"\xB8\x26\x00\x00\x00" +
    b"\x49\xBB" + ctypes.c_uint64(_LEGAL_SYSCALL_ADDR).value.to_bytes(8, 'little') +
    b"\x41\xFF\xE3" +
    b"\xC3"
)

_rvm_shellcode = (
    b"\x4C\x8B\xD1" +
    b"\xB8\x3F\x00\x00\x00" +
    b"\x49\xBB" + ctypes.c_uint64(_LEGAL_SYSCALL_ADDR).value.to_bytes(8, 'little') +
    b"\x41\xFF\xE3" +
    b"\xC3"
)

buf_op = _k32.VirtualAlloc(None, len(_op_shellcode), 0x1000 | 0x2000, _PAGE_ERW)
ctypes.memmove(buf_op, _op_shellcode, len(_op_shellcode))
_IndirectNtOpenProcess = ctypes.WINFUNCTYPE(
    wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.POINTER(OBJECT_ATTRIBUTES), ctypes.POINTER(CLIENT_ID)
)(buf_op)

buf_rvm = _k32.VirtualAlloc(None, len(_rvm_shellcode), 0x1000 | 0x2000, _PAGE_ERW)
ctypes.memmove(buf_rvm, _rvm_shellcode, len(_rvm_shellcode))
_IndirectNtReadVirtualMemory = ctypes.WINFUNCTYPE(
    wintypes.DWORD, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
)(buf_rvm)

def _indirect_open_process(pid):
    _0x3e1a_junk()
    handle = wintypes.HANDLE()
    client_id = CLIENT_ID(ctypes.c_void_p(pid), None)
    obj_attr = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), None, None, 0, None, None)
    if _IndirectNtOpenProcess(ctypes.byref(handle), 0x0010, ctypes.byref(obj_attr), ctypes.byref(client_id)) == 0:
        return handle.value
    return None

def _0x5d9a(handle, addr, c_type):
    buf = c_type()
    read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(addr), ctypes.byref(buf), ctypes.sizeof(c_type), ctypes.byref(read)) == 0:
        return buf.value
    return 0

def _0x7e2b(handle, addr, max_len=32):
    buf = ctypes.create_string_buffer(max_len)
    read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(addr), ctypes.byref(buf), max_len, ctypes.byref(read)) == 0:
        try: return buf.value.decode('utf-8', errors='ignore')
        except: return "Player"
    return "Player"

def _0x2f8c(handle, addr):
    class _V3(ctypes.Structure):
        _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("z", ctypes.c_float)]
    buf = _V3()
    read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(addr), ctypes.byref(buf), ctypes.sizeof(_V3), ctypes.byref(read)) == 0:
        return {"x": buf.x, "y": buf.y, "z": buf.z}
    return {"x": 0, "y": 0, "z": 0}

# --- 2026 STATIC OFFSETS ---
class _0x_Offsets: 
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

class _0x_Entity:
    def __init__(self, h, ctrl, pawn):
        self.h = h
        self.ctrl = ctrl
        self.pawn = pawn
    @property
    def team(self): return _0x5d9a(self.h, self.pawn + _0x_Offsets.m_iTeamNum, ctypes.c_int)
    @property
    def health(self): return _0x5d9a(self.h, self.pawn + _0x_Offsets.m_iHealth, ctypes.c_int)
    @property
    def pos(self): return _0x2f8c(self.h, self.pawn + _0x_Offsets.m_vOldOrigin)
    @property
    def name(self):
        if not self.ctrl: return "Player"
        return _0x7e2b(self.h, self.ctrl + _0x_Offsets.m_iszPlayerName, 32)
    @property
    def money(self):
        if not self.pawn: return 0
        srv = _0x5d9a(self.h, self.pawn + _0x_Offsets.m_pInGameMoneyServices, ctypes.c_uint64)
        if not srv: return 0
        return _0x5d9a(self.h, srv + _0x_Offsets.m_iAccount, ctypes.c_int)

def _0x1c8b(proc_name):
    snap = _k32.CreateToolhelp32Snapshot(0x00000002, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if _k32.Process32First(snap, ctypes.byref(pe)):
        while _k32.Process32Next(snap, ctypes.byref(pe)):
            if pe.szExeFile.decode('utf-8', errors='ignore').lower() == proc_name.lower():
                _k32.CloseHandle(snap)
                return pe.th32ProcessID
    _k32.CloseHandle(snap)
    return None

def _0x4f2c(pid, mod_name):
    snap = _k32.CreateToolhelp32Snapshot(0x00000008, pid)
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    if _k32.Module32First(snap, ctypes.byref(me)):
        while _k32.Module32Next(snap, ctypes.byref(me)):
            if me.szModule.decode('utf-8', errors='ignore').lower() == mod_name.lower():
                base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                _k32.CloseHandle(snap)
                return base
    _k32.CloseHandle(snap)
    return None

_shared_payload = {"yaw": 0, "local_team": 0, "players": []}

class _RadarHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): return
    def do_GET(self):
        global _shared_payload
        if self.path == '/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(_shared_payload).encode('utf-8'))
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(_HTML_DATA.encode('utf-8'))
        else:
            self.send_error(404)

def _start_srv():
    with socketserver.TCPServer(("0.0.0.0", 8000), _RadarHandler) as httpd:
        httpd.serve_forever()

_HTML_DATA = """
<!DOCTYPE html>
<html>
<head>
    <title>CS2 Indirect Tactical Dashboard</title>
    <style>
        body { margin: 0; background: #0b0e14; display: flex; color: #fff; font-family: sans-serif; height: 100vh; overflow: hidden; }
        .panel { display: flex; flex-direction: column; height: 100%; box-sizing: border-box; padding: 20px; background: #11141c; border-right: 2px solid #1c212e; }
        .team-panel { width: 28%; overflow-y: auto; }
        .team-title { font-size: 18px; font-weight: bold; padding-bottom: 10px; margin-bottom: 15px; border-bottom: 2px solid; text-align: center; }
        .team-my { color: #00ffcc; border-color: #00ffcc; }
        .team-enemy { color: #ff4444; border-color: #ff4444; }
        .player-card { background: #171c26; border-radius: 6px; padding: 12px; margin-bottom: 10px; border-left: 5px solid #8a96a3; display: flex; flex-direction: column; gap: 6px; }
        .player-card.alive { border-left-color: #44ff44; }
        .player-card.dead { border-left-color: #ff4444; opacity: 0.4; }
        .player-row { display: flex; justify-content: space-between; align-items: center; }
        .player-name { font-weight: bold; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .player-money { color: #2ecc71; font-weight: bold; font-family: monospace; }
        .hp-bar-bg { width: 100%; background: #222; height: 6px; border-radius: 3px; overflow: hidden; }
        .hp-bar-fill { height: 100%; background: #2ecc71; transition: width 0.1s; }
        .center-panel { width: 44%; display: flex; justify-content: center; align-items: center; position: relative; background: #0d1017; }
        canvas { background: #12161f; border-radius: 50%; border: 4px solid #242b35; box-shadow: 0 0 30px rgba(0,0,0,0.7); }
        .info-label { position: absolute; top: 20px; font-size: 14px; font-weight: bold; color: #526273; letter-spacing: 1px; }
    </style>
</head>
<body>
    <div class="panel team-panel"><div class="team-title team-my">MUTTEFIKLER</div><div id="myTeamList"></div></div>
    <div class="panel center-panel"><div class="info-label">INDIRECT SYSCALL RADAR</div><canvas id="radar" width="520" height="520"></canvas></div>
    <div class="panel team-panel" style="border-right: none;"><div class="team-title team-enemy">RAKIPLER</div><div id="enemyTeamList"></div></div>
    <script>
        const canvas = document.getElementById('radar'); const ctx = canvas.getContext('2d'); const center = canvas.width / 2; const SCALE = 0.16;
        function drawRadarGrid() {
            ctx.clearRect(0, 0, canvas.width, canvas.height); ctx.strokeStyle = '#1f2533'; ctx.lineWidth = 1;
            for(let r = 80; r <= center; r += 80) { ctx.beginPath(); ctx.arc(center, center, r, 0, 2 * Math.PI); ctx.stroke(); }
            ctx.beginPath(); ctx.moveTo(center, 0); ctx.lineTo(center, canvas.height); ctx.moveTo(0, center); ctx.lineTo(canvas.width, center); ctx.stroke();
            ctx.fillStyle = '#00ffcc'; ctx.beginPath(); ctx.moveTo(center, center - 10); ctx.lineTo(center - 7, center + 7); ctx.lineTo(center + 7, center + 7); closedPath(); ctx.fill();
        }
        function createPlayerCard(p) {
            const status = p.health > 0 ? 'alive' : 'dead'; const hpW = Math.max(0, Math.min(100, p.health));
            let hpC = p.health < 35 ? '#e74c3c' : (p.health < 70 ? '#f1c40f' : '#2ecc71');
            return `<div class="player-card ${status}"><div class="player-row"><span class="player-name">${p.name}</span><span class="player-money">$${p.money}</span></div><div class="hp-bar-bg"><div class="hp-bar-fill" style="width: ${hpW}%; background-color: ${hpC};"></div></div></div>`;
        }
        async function updateDashboard() {
            try {
                const res = await fetch('/data'); const d = await res.json(); drawRadarGrid(); const yawRad = (d.yaw * Math.PI) / 180;
                let myHTML = ""; let enHTML = "";
                d.players.forEach(p => {
                    if (p.team === d.local_team) myHTML += createPlayerCard(p); else enHTML += createPlayerCard(p);
                    if (p.health > 0 && !p.is_local) {
                        let rx = p.dx * Math.cos(-yawRad) - p.dy * Math.sin(-yawRad); let ry = p.dx * Math.sin(-yawRad) + p.dy * Math.cos(-yawRad);
                        let sX = center + (rx * SCALE); let sY = center - (ry * SCALE);
                        if (Math.sqrt(Math.pow(sX - center, 2) + Math.pow(sY - center, 2)) < center - 10) {
                            ctx.fillStyle = p.team === d.local_team ? '#00ffcc' : '#ff4444'; ctx.beginPath(); ctx.arc(sX, sY, 6, 0, 2 * Math.PI); ctx.fill();
                            ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
                        }
                    }
                });
                document.getElementById('myTeamList').innerHTML = myHTML; document.getElementById('enemyTeamList').innerHTML = enHTML;
            } catch (e) {}
            setTimeout(updateDashboard, 30);
        }
        updateDashboard();
    </script>
</body>
</html>
"""

def main():
    global _shared_payload
    pid = None
    while pid is None:
        pid = _0x1c8b("cs2.exe")
        if pid is None:
            time.sleep(1)

    handle = _indirect_open_process(pid)
    if not handle:
        return

    base = _0x4f2c(pid, "client.dll")

    t = threading.Thread(target=_start_srv, daemon=True)
    t.start()

    print("[+] Dolayli (Indirect) Syscall Motoru Stabilize Edildi.")

    while True:
        try:
            if random.random() < 0.05:
                _0x3e1a_junk()

            _EntList = _0x5d9a(handle, base + _0x_Offsets.dwEntityList, ctypes.c_uint64)
            _LocalPawn = _0x5d9a(handle, base + _0x_Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            _Input = _0x5d9a(handle, base + _0x_Offsets.dwCSGOInput, ctypes.c_uint64)
            
            if not _LocalPawn or not _Input:
                time.sleep(0.1)
                continue
                
            local = _0x_Entity(handle, 0, _LocalPawn)
            l_pos = local.pos
            l_team = local.team
            yaw = _0x5d9a(handle, _Input + 0x44, ctypes.c_float)

            temp_p = []

            for i in range(1, 64):
                le1 = _0x5d9a(handle, _EntList + (8 * (i & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                if le1 == 0: continue   
                ent = _0x5d9a(handle, le1 + 112 * (i & 0x1FF), ctypes.c_uint64)
                if ent == 0: continue                          
                entPawnRef = _0x5d9a(handle, ent + _0x_Offsets.m_hPlayerPawn, ctypes.c_uint)
                if entPawnRef == 0: continue   
                le2 = _0x5d9a(handle, _EntList + 0x8 * ((entPawnRef & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                if le2 == 0: continue 
                pawnAddr = _0x5d9a(handle, le2 + 112 * (entPawnRef & 0x1FF), ctypes.c_uint64)
                if pawnAddr == 0: continue 

                p = _0x_Entity(handle, ent, pawnAddr)
                p_pos = p.pos

                temp_p.append({
                    "name": p.name, "health": p.health, "money": p.money, "team": p.team,
                    "is_local": (pawnAddr == _LocalPawn),
                    "dx": p_pos["x"] - l_pos["x"], "dy": p_pos["y"] - l_pos["y"]
                })

            _shared_payload = {"yaw": yaw, "local_team": l_team, "players": temp_p}
            time.sleep(random.uniform(0.015, 0.025))
                
        except Exception:
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    main()
        
