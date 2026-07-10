import os
import requests
from flask import Flask, request, jsonify
import time
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import threading
import subprocess
import atexit

app = Flask(__name__)
sign_lock = threading.Lock()

# Start Node.js Sign Bridge
node_proc = None
try:
    node_path = 'node.exe'
    if not os.path.exists(node_path):
        import urllib.request
        print(">>> Downloading portable Node.js runtime (node.exe)...")
        # Direct download link for Node.js portable win-x64
        urllib.request.urlretrieve("https://nodejs.org/dist/v20.11.0/win-x64/node.exe", node_path)
        print(">>> Node.js download completed successfully.")
        
    node_bin = './node.exe' if os.path.exists(node_path) else 'node'
    node_proc = subprocess.Popen([node_bin, 'v4_test/server/sign_bridge.js', '--serve', '19876'])
    def cleanup():
        if node_proc: node_proc.terminate()
    atexit.register(cleanup)
except Exception as e:
    print(">>> Error starting Node.js sign bridge:", e)

@app.route('/')
def index():
    return "Flowborn V4 Server Running"

@app.route('/proxy', methods=['POST'])
def proxy():
    data = request.json
    if not data: return jsonify({"code": -1, "msg": "Invalid JSON"}), 400
    
    # [Placeholder] Real license check would go here
    # is_valid = check_did(data.get('did'))
    
    endpoint = data.get('endpoint')
    payload = data.get('payload', {})
    headers = data.get('headers', {})
    
    try:
        for h in ['host', 'content-length', 'connection', 'accept-encoding']:
            headers.pop(h, None)
            
        r = requests.post(
            "https://kgvn-api.mobagarena.com" + endpoint,
            json=payload,
            headers=headers,
            timeout=30
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"code": -1, "msg": str(e)}), 500

@app.route('/get_signature', methods=['POST'])
def get_signature():
    data = request.json
    encryption = data.get('encryption')
    camp_roleid = data.get('campRoleid', '')
    roleid = data.get('roleid', '')
    
    if not node_proc:
        return jsonify({"encodeparam": "node_not_running_fallback"}), 200
        
    with sign_lock:
        try:
            requests.post('http://127.0.0.1:19876/init', json={'encryption': encryption, 'campRoleid': camp_roleid}, timeout=5)
            r = requests.post('http://127.0.0.1:19876/sign', json={'roleid': roleid}, timeout=5)
            return jsonify(r.json())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
