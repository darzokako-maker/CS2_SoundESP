import sys
import time
from math import sqrt, inf
import ctypes
from ctypes import wintypes

# --- Windows Hafıza Okuma API Yapılandırması (pyMeow Alternatifi) ---
kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HANDLE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260)
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

# --- Ofset Yapılandırması (2026 Dump) ---
class Config:
    distance = 1300

class Offsets: 
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          

class Entity:
    def __init__(self, handle, pawn):
        self.handle = handle
        self.pawn = pawn
    
    @property
    def team(self):
        return read_memory(self.handle, self.pawn + Offsets.m_iTeamNum, ctypes.c_int)
    
    @property
    def health(self):
        return read_memory(self.handle, self.pawn + Offsets.m_iHealth, ctypes.c_int)

    @property
    def position(self):
        return read_vec3(self.handle, self.pawn + Offsets.m_vOldOrigin)

def distance(player, entity):
    return sqrt((player["x"] - entity["x"])**2 + (player["y"] - entity["y"])**2 + (player["z"] - entity["z"])**2)

def main():
    pid = None
    while pid is None:
        pid = get_process_id("cs2.exe")
        if pid is None:
            sys.stdout.write("\r[ Waiting ] CS2.exe bekleniyor... Lutfen oyunu baslatin. \x1b[K")
            sys.stdout.flush()
            time.sleep(1)

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    base = get_module_base(pid, "client.dll")

    print("\n[+] CS2 Basariyla Bulundu ve Yerel API ile Baglanildi!")
    print("[+] Started CS2 Terminal ESP with updated 2026 offsets.")
    print("--------------------------------------------------")

    while True:
        try:
            EntityList = read_memory(handle, base + Offsets.dwEntityList, ctypes.c_uint64)
            localPlayerPawnAddr = read_memory(handle, base + Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            
            if not localPlayerPawnAddr:
                time.sleep(0.5)
                continue
                
            localPlayer = Entity(handle, localPlayerPawnAddr)
            lowestDist = inf

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
                    local_pos = localPlayer.position
                    player_pos = player.position
                    
                    if local_pos["x"] == 0 and player_pos["x"] == 0:
                        continue
                        
                    dist = distance(local_pos, player_pos)
                    if dist < lowestDist:
                        lowestDist = dist

            if lowestDist < Config.distance:
                duration = max(150, lowestDist / 2)
                sys.stdout.write(f"\r[DUSMAN YAKINDA] En Yakin Dusman Mesafesi: {lowestDist:.2f} birim \x1b[K")
                sys.stdout.flush()
                time.sleep(duration / 2500)
            else:
                sys.stdout.write("\r[GUVENLI] Belirlenen mesafede dusman yok. \x1b[K")
                sys.stdout.flush()
                time.sleep(.5)
                
        except Exception:
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    main()
    
