"""
External CS2 Terminal Distance ESP
by im-razvan (Offsets updated from 2026 dump files)
"""

import sys
from math import sqrt, inf
from time import sleep

# Kütüphane Kontrolü: Derleme sonrası eksik bağımlılık senaryolarına karşı önlem
try:
    import pyMeow as pm
except ImportError:
    print("[-] HATA: 'pyMeow' kutuphanesi yuklenemedi veya eksik.")
    print("Lutfen programi yonetici olarak calistirdiginizdan emin olun.")
    input("\nKapatmak icin ENTER'a basin...")
    sys.exit(1)

class Config:
    distance = 1300

class Offsets: 
    # 2026 Tarihli offsets.hpp Dosyasından Alınan Güncel Ana Adresler
    dwEntityList = 0x24E76A0       
    dwLocalPlayerPawn = 0x2341698  

    # 2026 Tarihli client_dll.hpp Dosyasından Alınan Güncel Sınıf İçi Ofsetler
    m_iTeamNum = 0x3EB             
    m_iHealth = 0x34C              
    m_vOldOrigin = 0x1390          
    m_hPlayerPawn = 0x90C          

class Entity:
    def __init__(self, proc, pawn):
        self.proc = proc
        self.pawn = pawn
    
    @property
    def team(self):
        try:
            return pm.r_int(self.proc, self.pawn + Offsets.m_iTeamNum)
        except:
            return 0
    
    @property
    def health(self):
        try:
            return pm.r_int(self.proc, self.pawn + Offsets.m_iHealth)
        except:
            return 0

    @property
    def position(self):
        try:
            return pm.r_vec3(self.proc, self.pawn + Offsets.m_vOldOrigin)
        except:
            return {"x": 0, "y": 0, "z": 0}

def distance(player, entity):
    return sqrt((player["x"] - entity["x"])**2 + (player["y"] - entity["y"])**2 + (player["z"] - entity["z"])**2)

def main():
    proc = None
    
    # Oyun açılana kadar döngüde bekler, açılınca otomatik bağlanır
    while proc is None:
        try:
            proc = pm.open_process("cs2.exe")
            base = pm.get_module(proc, "client.dll")["base"]
        except:
            sys.stdout.write("\r[ Waiting ] CS2.exe bekleniyor... Lutfen oyunu baslatin. \x1b[K")
            sys.stdout.flush()
            sleep(1)

    print("\n[+] CS2 Basariyla Bulundu ve Baglanildi!")
    print("[+] Started CS2 Terminal ESP with updated 2026 offsets.")
    print("--------------------------------------------------")

    while True:
        try:
            EntityList = pm.r_uint64(proc, base + Offsets.dwEntityList)
            localPlayerPawnAddr = pm.r_uint64(proc, base + Offsets.dwLocalPlayerPawn)
            
            if not localPlayerPawnAddr:
                sleep(0.5)
                continue
                
            localPlayer = Entity(proc, localPlayerPawnAddr)
            lowestDist = inf

            for i in range(1, 64):
                listEntry = pm.r_uint64(proc, EntityList + (8 * (i & 0x7FFF) >> 9) + 16)
                if listEntry == 0: continue   
                entity = pm.r_uint64(proc, listEntry + 112 * (i & 0x1FF))
                if entity == 0: continue                          
                entityCPawn = pm.r_uint(proc, entity + Offsets.m_hPlayerPawn)
                if entityCPawn == 0: continue   
                listEntry2  = pm.r_uint64(proc, EntityList + 0x8 * ((entityCPawn & 0x7FFF) >> 9) + 16)
                if listEntry2 == 0: continue 
                entityPawn = pm.r_uint64(proc, listEntry2 + 112 * (entityCPawn & 0x1FF))
                if entityPawn == 0: continue 

                player = Entity(proc, entityPawn)

                if localPlayer.team != player.team and player.health > 0:
                    local_pos = localPlayer.position
                    player_pos = player.position
                    
                    # Geçersiz koordinat kontrolü
                    if local_pos["x"] == 0 and player_pos["x"] == 0:
                        continue
                        
                    dist = distance(local_pos, player_pos)
                    if dist < lowestDist:
                        lowestDist = dist

            # Mesafe ekran çıktısı kontrolü
            if lowestDist < Config.distance:
                duration = max(150, lowestDist / 2)
                sys.stdout.write(f"\r[DUSMAN YAKINDA] En Yakin Dusman Mesafesi: {lowestDist:.2f} birim \x1b[K")
                sys.stdout.flush()
                sleep(duration / 2500)
            else:
                sys.stdout.write("\r[GUVENLI] Belirlenen mesafede dusman yok. \x1b[K")
                sys.stdout.flush()
                sleep(.5)
                
        except Exception:
            # Raunt geçişlerinde oluşabilecek anlık okuma sapmalarında çökmesini önler
            sleep(0.1)
            continue

if __name__ == "__main__":
    main()
    
