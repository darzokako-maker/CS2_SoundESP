import subprocess
import time
import sys
import os

def main():
    print("[*] CS2 Web Radar Sistemi Baslatiliyor...")
    
    # 1. Arka planda hafıza motorunu çalıştır
    try:
        server_process = subprocess.Popen([sys.executable, "radar_server.py"])
        print("[+] radar_server.py baslatildi.")
    except Exception as e:
        print(f"[-] radar_server.py tetiklenemedi: {e}")
        return

    # Motorun portu rezerve etmesi için bekleme süresi
    time.sleep(1.5)

    # 2. Web arayüzünü çalıştır ve bu süreç bitene kadar açık kal
    try:
        print("[+] web_interface.py baslatiliyor...")
        # wait() yerine doğrudan çalıştırarak logların düşmesini sağlıyoruz
        subprocess.Popen([sys.executable, "web_interface.py"]).wait()
    except KeyboardInterrupt:
        print("\n[-] Sistem kapatiliyor...")
        server_process.terminate()
    except Exception as e:
        print(f"[-] web_interface.py baslatilamadi: {e}")
        server_process.terminate()

if __name__ == "__main__":
    main()
    
