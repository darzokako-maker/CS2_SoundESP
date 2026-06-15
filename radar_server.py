import sys
import time
import math
import ctypes
from ctypes import wintypes
from multiprocessing.managers import BaseManager

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

def read_string(handle, address, max_len=32):
    buffer = ctypes.create_string_buffer(max_len)
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), max_len, ctypes.byref(bytes_read)) == 0:
        try: return buffer.value.decode('utf-8', errors='ignore')
        except: return "Unknown"
    return "Unknown"

def read_vec3(handle, address):
    class Vec3(ctypes.Structure):
        _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("z", ctypes.c_float)]
    buffer = Vec3()
    bytes_read = ctypes.c_size_t()
    if _IndirectNtReadVirtualMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(Vec3), ctypes.byref(bytes_read)) == 0:
        return {"x": buffer.x, "y": buffer.y, "z": buffer.z}
    return {"x": 0, "y": 0, "z": 0}

class Offsets: 
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          
    m_iszPlayerName = 0x638        
    m_pInGameMoneyServices = 0x6F8 
    m_iAccount = 0x40              
    m_angEyeAngles = 0x14F8        
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
        if not self.controller: return 0
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
        if "weapon_" in full_name: return full_name.replace("weapon_", "").upper()
        return full_name.upper()

# --- IPC Veri Paylaşım Sunucusu Kurulumu ---
shared_data = {"yaw": 0, "local_team": 0, "players": []}

def get_shared_data():
    return shared_data

class TokenManager(BaseManager): pass

def main():
    global shared_data
    TokenManager.register('get_radar_data', callable=get_shared_data)
    manager = TokenManager(address=('127.0.0.1', 50001), authkey=b'radar_secret')
    manager.start()
    print("[+] IPC Veri Havuzu Port 50001 uzerinde baslatildi.")

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
    if not base: return

    print("\n[+] Taktiksel Hafiza Motoru Aktif.")
    
    try:
        while True:
            EntityList = read_memory(handle, base + Offsets.dwEntityList, ctypes.c_uint64)
            local_player_pawn = read_memory(handle, base + Offsets.dwLocalPlayerPawn, ctypes.c_uint64)
            
            if local_player_pawn and EntityList:
                local_team = read_memory(handle, local_player_pawn + Offsets.m_iTeamNum, ctypes.c_int)
                local_pos = read_vec3(handle, local_player_pawn + Offsets.m_vOldOrigin)
                local_yaw = read_memory(handle, local_player_pawn + Offsets.m_angEyeAngles + 4, ctypes.c_float)
                
                temp_players = []
                for i in range(1, 64):
                    listEntry = read_memory(handle, EntityList + (8 * (i & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                    if listEntry == 0: continue   
                    entity = read_memory(handle, listEntry + 112 * (i & 0x1FF), ctypes.c_uint64)
                    if entity == 0: continue                          
                    entityCPawn = read_memory(handle, entity + Offsets.m_hPlayerPawn, ctypes.c_uint)
                    if entityCPawn == 0: continue   
                    listEntry2 = read_memory(handle, EntityList + 0x8 * ((entityCPawn & 0x7FFF) >> 9) + 16, ctypes.c_uint64)
                    if listEntry2 == 0: continue 
                    entityPawn = read_memory(handle, listEntry2 + 112 * (entityCPawn & 0x1FF), ctypes.c_uint64)
                    if entityPawn == 0: continue 

                    player = Entity(handle, entity, entityPawn, EntityList)
                    player_pos = player.position
                    is_local = (entityPawn == local_player_pawn)

                    temp_players.append({
                        "name": player.name, "health": player.health, "money": player.money,
                        "weapon": player.weapon, "team": player.team, "yaw": player.yaw,
                        "is_local": is_local, "dx": player_pos["x"] - local_pos["x"], "dy": player_pos["y"] - local_pos["y"]
                    })

                # Paylaşılan veriyi güvenli bir şekilde güncelle
                shared_data.update({
                    "yaw": local_yaw, "local_team": local_team, "players": temp_players
                })
            time.sleep(0.015)
    except KeyboardInterrupt:
        print("\n[-] Motor Durduruldu.")

if __name__ == "__main__":
    main()

