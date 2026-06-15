import subprocess
import time
import sys

def main():
    print("[*] CS2 Web Radar Sistemi Baslatiliyor...")
    
    # 1. Arka planda hafiza motorunu (radar_server) baslat
    try:
        server_process = subprocess.Popen([sys.executable, "radar_server.py"])
        print("[+] Hafiza motoru (radar_server.py) arka planda tetiklendi.")
    except Exception as e:
        print(f"[-] radar_server.py baslatilamadi: {e}")
        return

    # Motorun ayağa kalkması ve portu rezerve etmesi için kısa bir bekleme süresi
    time.sleep(1.5)

    # 2. Web arayuz sunucusunu baslat ve bu sureç bitene kadar ana kodu acik tut
    try:
        print("[+] Web sunucusu (web_interface.py) baslatiliyor...")
        subprocess.Popen([sys.executable, "web_interface.py"]).wait()
    except KeyboardInterrupt:
        print("\n[-] Kullanici istegiyle kapatiliyor...")
        server_process.terminate()
    except Exception as e:
        print(f"[-] web_interface.py baslatilamadi: {e}")
        server_process.terminate()

if __name__ == "__main__":
    main()
    
