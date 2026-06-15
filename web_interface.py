import http.server
import socketserver
import json
import sys
import os
from multiprocessing.managers import BaseManager

# PyInstaller geçici klasör dizini kontrolü (EXE olarak çalışırken burayı kullanır)
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

class TokenManager(BaseManager): pass
TokenManager.register('get_radar_data')

try:
    manager = TokenManager(address=('127.0.0.1', 50001), authkey=b'radar_secret')
    manager.connect()
    remote_radar_data = manager.get_radar_data()
    print("[+] Radar Veri Motoruna Basariyla Baglanildi.")
except Exception as e:
    print("[-] Hata: 'radar_server.py' acik degil! Once motoru baslatmalisin.")
    sys.exit(1)

class RadarWebHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): return
    def do_GET(self):
        if self.path == '/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            local_dict = dict(remote_radar_data)
            self.wfile.write(json.dumps(local_dict).encode('utf-8'))
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_RADAR_UI.encode('utf-8'))
        else:
            self.send_error(404)

# --- WEB PANEL ARAYÜZÜ (HTML) ---
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
                            
                            ctx.strokeStyle = color;
                            ctx.lineWidth = 2.5;
                            ctx.beginPath();
                            ctx.moveTo(screenX, screenY);
                            let lineLength = 15;
                            ctx.lineTo(screenX + Math.sin(relativeYaw) * lineLength, screenY - Math.cos(relativeYaw) * lineLength);
                            ctx.stroke();

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

def run_web_server():
    PORT = 8000
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), RadarWebHandler) as httpd:
        print(f"[+] Web Arayuzu Baslatildi: http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_web_server()
    
