"""
External CS2 Terminal Distance ESP
by im-razvan (Offsets updated from 2026 dump files)
"""

import pyMeow as pm
from math import sqrt, inf
from time import sleep
import sys

class Config:
    distance = 1300

class Offsets: 
    # 11.06.2026 Tarihli offsets.hpp Dosyasından Alınan Güncel Ana Adresler
    dwEntityList = 0x24E76A0       # offsets.hpp -> dwEntityList
    dwLocalPlayerPawn = 0x2341698  # offsets.hpp -> dwLocalPlayerPawn

    # 11.06.2026 Tarihli client_dll.hpp Dosyasından Alınan Güncel Sınıf İçi Ofsetler
    m_iTeamNum = 0x3EB             # client_dll.hpp -> C_BaseEntity -> m_iTeamNum
    m_iHealth = 0x34C              # client_dll.hpp -> C_BaseEntity -> m_iHealth
    m_vOldOrigin = 0x1390          # client_dll.hpp -> C_BasePlayerPawn -> m_vOldOrigin
    m_hPlayerPawn = 0x90C          # client_dll.hpp -> CCSPlayerController -> m_hPlayerPawn

class Entity:
    def __init__(self, proc, pawn):
        self.proc = proc
        self.pawn = pawn
    
    @property
    def team(self):
        return pm.r_int(self.proc, self.pawn + Offsets.m_iTeamNum)
    
    @property
    def health(self):
        return pm.r_int(self.proc, self.pawn + Offsets.m_iHealth)

    @property
    def position(self):
        return pm.r_vec3(self.proc, self.pawn + Offsets.m_vOldOrigin)

def distance(player, entity):
    return sqrt((player["x"] - entity["x"])**2 + (player["y"] - entity["y"])**2 + (player["z"] - entity["z"])**2)

def main():
    try:
        proc = pm.open_process("cs2.exe")
        base = pm.get_module(proc, "client.dll")["base"]
    except Exception as e:
        print(f"Hata: CS2 acik degil veya client.dll bulunamadi! ({e})")
        return

    print("Started CS2 Terminal ESP with updated 2026 offsets.")
    print("--------------------------------------------------")

    while True:
        EntityList = pm.r_uint64(proc, base + Offsets.dwEntityList)

        localPlayer = Entity(proc, pm.r_uint64(proc, base + Offsets.dwLocalPlayerPawn))

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
                dist = distance(localPlayer.position, player.position)
                if dist < lowestDist:
                    lowestDist = dist

        # SES YERİNE TERMİNALE BASMA MANTIĞI (Projedeki Yapı Aynen Korundu)
        if lowestDist < Config.distance:
            duration = max(150, lowestDist / 2)
            
            # \r imleci satırın başına çeker, \x1b[K ise eski satırdan kalan yazıları siler.
            # Böylece terminal pencereni kirletmeden tek satır üzerinde akıcı olarak mesafe takibi yapabilirsin.
            sys.stdout.write(f"\r[DUSMAN YAKINDA] En Yakin Dusman Mesafesi: {lowestDist:.2f} birim \x1b[K")
            sys.stdout.flush()
            
            sleep(duration / 2500)
        else:
            sys.stdout.write("\r[GUVENLI] Belirlenen mesafede dusman yok. \x1b[K")
            sys.stdout.flush()
            sleep(.5)

if __name__ == "__main__":
    main()
    
