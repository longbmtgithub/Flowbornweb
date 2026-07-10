import os
import requests
import io
import time
import json
import hashlib
import hmac as hmac_lib
import subprocess
import tempfile
import threading
import webbrowser
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import logging
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, redirect
from playwright.sync_api import sync_playwright
from PIL import Image as _PIL_Image

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24).hex()

USERS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "users.json")

def load_users():
    if not os.path.exists(USERS_FILE):
        default_users = {
            "admin": "admin123"
        }
        try:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(default_users, f, indent=2)
        except Exception:
            pass
        return default_users
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"admin": "admin123"}

GIST_ID = "a104c4c7c27608d9420e7ce94578b56c"

def load_gist_token():
    # 1. Check in v4_test/
    token_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".gist_token")
    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except:
            pass
    # 2. Check in root/
    root_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".gist_token")
    if os.path.exists(root_path):
        try:
            with open(root_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except:
            pass
    return None

def fetch_gist_data(token=None):
    if not token:
        token = load_gist_token()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        r = requests.get(f"https://api.github.com/gists/{GIST_ID}", headers=headers, timeout=15)
        r.raise_for_status()
    except Exception as e:
        if token:
            try:
                # Fallback to fetch without token for public gist
                r = requests.get(f"https://api.github.com/gists/{GIST_ID}", headers={"Accept": "application/vnd.github.v3+json"}, timeout=15)
                r.raise_for_status()
            except Exception:
                raise e
        else:
            raise e
    content = r.json()["files"]["licenses.json"]["content"]
    return json.loads(content)

def save_gist_data(data, token=None):
    if not token:
        token = load_gist_token()
    if not token:
        raise Exception("Gist token not found")
    content = json.dumps(data, indent=2, ensure_ascii=False)
    r = requests.patch(
        f"https://api.github.com/gists/{GIST_ID}",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
        json={"files": {"licenses.json": {"content": content}}},
        timeout=15
    )
    return r.status_code == 200

@app.before_request
def check_auth():
    allowed_paths = ["/login", "/api/login_auth", "/favicon.ico"]
    if request.path.startswith("/static/"):
        return
    if request.path in allowed_paths:
        return
    if not session.get("authenticated"):
        return redirect("/login")

@app.route('/login')
def login():
    if session.get("authenticated"):
        return redirect("/")
    return render_template('login.html')

@app.route('/api/login_auth', methods=['POST'])
def api_login_auth():
    try:
        data = request.json or {}
        username = (data.get("username") or "").strip().lower()
        password = data.get("password") or ""
        
        if not username or not password:
            return jsonify({"success": False, "error": "Vui lòng nhập tài khoản và mật khẩu!"})
            
        if username == "admin":
            users = load_users()
            if username in users and users[username] == password:
                session["authenticated"] = True
                session["username"] = username
                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "error": "Tên đăng nhập hoặc mật khẩu không chính xác!"})
                
        # Authenticate non-admin against Gist accounts
        try:
            gist_data = fetch_gist_data()
            accs = gist_data.get("accounts", {})
            if username in accs:
                acc = accs[username]
                if acc.get("status", "approved") == "pending":
                    return jsonify({"success": False, "error": "Tài khoản của bạn đang chờ admin phê duyệt!"})
                
                # Compute hash matching index.html creation
                salt_msg = password + "_fp_salt_" + username
                h = hashlib.sha256(salt_msg.encode('utf-8')).hexdigest()
                
                if acc.get("pass") == h:
                    session["authenticated"] = True
                    session["username"] = username
                    return jsonify({"success": True})
            
            return jsonify({"success": False, "error": "Tên đăng nhập hoặc mật khẩu không chính xác!"})
        except Exception as ge:
            return jsonify({"success": False, "error": f"Lỗi xác thực database bản quyền: {ge}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/logout')
def session_logout():
    session.clear()
    return redirect('/login')

def check_admin_permission():
    if session.get("username") != "admin":
        return False
    return True

@app.route('/admin/users')
def admin_users():
    if not check_admin_permission():
        return redirect('/')
    return render_template('admin_users.html')

@app.route('/api/admin/users', methods=['GET'])
def api_get_users():
    if not check_admin_permission():
        return jsonify({"success": False, "error": "Không có quyền truy cập!"}), 403
    try:
        gist_data = fetch_gist_data()
        accs = gist_data.get("accounts", {})
        users_dict = {}
        for u, info in accs.items():
            users_dict[u] = info.get("raw_pass") or "********"
        # Include local admin password
        local_u = load_users()
        if "admin" in local_u:
            users_dict["admin"] = local_u["admin"]
        return jsonify(users_dict)
    except Exception as e:
        return jsonify({"success": False, "error": f"Lỗi Gist: {e}"})

@app.route('/api/admin/users/add', methods=['POST'])
def api_add_user():
    if not check_admin_permission():
        return jsonify({"success": False, "error": "Không có quyền truy cập!"}), 403
    try:
        data = request.json or {}
        username = (data.get("username") or "").strip().lower()
        password = (data.get("password") or "").strip()
        
        if not username or not password:
            return jsonify({"success": False, "error": "Vui lòng nhập tài khoản và mật khẩu!"})
            
        if username == "admin":
            users = load_users()
            users["admin"] = password
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
            return jsonify({"success": True})
            
        gist_data = fetch_gist_data()
        accs = gist_data.setdefault("accounts", {})
        if username in accs:
            return jsonify({"success": False, "error": "Tài khoản đã tồn tại trên Gist!"})
            
        # Compute SHA-256 hash
        salt_msg = password + "_fp_salt_" + username
        h = hashlib.sha256(salt_msg.encode('utf-8')).hexdigest()
        
        accs[username] = {
            "pass": h,
            "name": username,
            "devices": [],
            "created": time.strftime('%Y-%m-%d'),
            "status": "approved",
            "raw_pass": password
        }
        
        # Also create a web license entry in gist if not exists
        wl = gist_data.setdefault("web_licenses", {})
        wl[username] = {
            "max": 999,
            "name": username
        }
        
        if save_gist_data(gist_data):
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Lỗi lưu Gist!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/admin/users/edit', methods=['POST'])
def api_edit_user():
    if not check_admin_permission():
        return jsonify({"success": False, "error": "Không có quyền truy cập!"}), 403
    try:
        data = request.json or {}
        username = (data.get("username") or "").strip().lower()
        password = (data.get("password") or "").strip()
        
        if not username or not password:
            return jsonify({"success": False, "error": "Vui lòng nhập đầy đủ thông tin!"})
            
        if username == "admin":
            users = load_users()
            users["admin"] = password
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
            return jsonify({"success": True})
            
        gist_data = fetch_gist_data()
        accs = gist_data.setdefault("accounts", {})
        if username not in accs:
            return jsonify({"success": False, "error": "Tài khoản không tồn tại trên Gist!"})
            
        salt_msg = password + "_fp_salt_" + username
        h = hashlib.sha256(salt_msg.encode('utf-8')).hexdigest()
        
        accs[username]["pass"] = h
        accs[username]["raw_pass"] = password
        
        # Also update in web_licenses
        wl = gist_data.setdefault("web_licenses", {})
        if username in wl:
            wl[username]["name"] = username
            
        if save_gist_data(gist_data):
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Lỗi lưu Gist!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/admin/users/delete', methods=['POST'])
def api_delete_user():
    if not check_admin_permission():
        return jsonify({"success": False, "error": "Không có quyền truy cập!"}), 403
    try:
        data = request.json or {}
        username = (data.get("username") or "").strip().lower()
        
        if not username:
            return jsonify({"success": False, "error": "Thiếu tên tài khoản!"})
            
        if username == "admin":
            return jsonify({"success": False, "error": "Không thể xóa tài khoản admin mặc định!"})
            
        gist_data = fetch_gist_data()
        accs = gist_data.setdefault("accounts", {})
        if username not in accs:
            return jsonify({"success": False, "error": "Tài khoản không tồn tại trên Gist!"})
            
        # Delete linked devices licenses if any
        devs = accs[username].get("devices", [])
        lics = gist_data.get("licenses", {})
        for d in devs:
            if d in lics:
                del lics[d]
                
        del accs[username]
        
        # Delete web license
        wl = gist_data.get("web_licenses", {})
        if username in wl:
            del wl[username]
            
        if save_gist_data(gist_data):
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Lỗi lưu Gist!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

PROXY_URL = "http://127.0.0.1:5000"

_garena_auth_sessions = {}

def get_current_garena_auth():
    username = session.get("username", "guest")
    return _garena_auth_sessions.get(username)

# Real-time Web Logging queue
_log_queue = []
_log_lock = threading.Lock()

def log_to_web(msg, type='info'):
    with _log_lock:
        _log_queue.append({
            "time": time.strftime("%H:%M:%S"),
            "msg": msg,
            "type": type
        })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    global _log_queue
    with _log_lock:
        logs = list(_log_queue)
        _log_queue.clear()
    return jsonify(logs)

# =============================================================================
# MEDIA PROCESSING CONSTANTS
# =============================================================================

COS_BUCKET          = "aovcamp-h5-ugc-1254801811"
COS_REGION          = "ap-singapore"
COS_HOST            = "{}.cos.{}.myqcloud.com".format(COS_BUCKET, COS_REGION)
CDN_BASE            = "https://kg-camp-ugc.mobagarena.com"
CDN_OFFICIAL        = "https://kg-camp.mobagarena.com"
API_BASE            = "https://kgvn-api.mobagarena.com"

ROLE_CONFIGS = {
    (1, 1): {"id": 28, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/ZeoMxjHs.png"}, # Tank Nam
    (1, 2): {"id": 29, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/ZeoMxjHs.png"}, # Tank Nu
    (2, 1): {"id": 34, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Warrior Nam
    (2, 2): {"id": 35, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Warrior Nu
    (3, 1): {"id": 30, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Assassin Nam
    (3, 2): {"id": 31, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Assassin Nu
    (4, 1): {"id": 62, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/5fXAjyuq.png"}, # Mage Nam
    (4, 2): {"id": 63, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/5fXAjyuq.png"}, # Mage Nu
    (5, 1): {"id": 32, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Archer Nam
    (5, 2): {"id": 33, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"}, # Archer Nu
    (6, 1): {"id": 60, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/5fXAjyuq.png"}, # Support Nam
    (6, 2): {"id": 61, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/5fXAjyuq.png"}, # Support Nu
}

# LoadTran (Playerimage) constants
PI_BG_ID            = "21"
PI_BG_PICURL        = CDN_BASE + "/manage/playerimage_official/iDzT817p.png"
PI_BG_W             = 320
PI_BG_H             = 503.9935570469799

# Flowborn Preset 1 & 2
STICKER_PRESETS = {
    "1": {
        "width": 484.20, "height": 484.20,
        "posX": -124.25, "posY": -76.04
    },
    "2": {
        "width": 512.00, "height": 512.00,
        "posX": -128.00, "posY": -128.00
    }
}

FIXED_HEADERS = {
    "camp-source":        "AOV-CAMP",
    "msdk-gameid":        "1137",
    "camp-authtype":      "msdk",
    "areaid":             "1",
    "msdk-os":            "1",
    "logicworldid":       "1011",
    "aov-language":       "VN",
    "msdk-channelid":     "10",
    "aov-region":         "1137",
    "origin":             "https://kgvn-camp.mobagarena.com",
    "x-requested-with":   "com.garena.game.kgvn",
    "referer":            "https://kgvn-camp.mobagarena.com/",
    "sec-ch-ua-mobile":   "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-site":     "same-site",
    "sec-fetch-mode":     "cors",
    "sec-fetch-dest":     "empty",
    "accept":             "*/*",
    "accept-language":    "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "accept-encoding":    "gzip, deflate, br, zstd",
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def gen_traceparent():
    return "00-{}-{}-01".format(os.urandom(16).hex(), os.urandom(8).hex())

def ensure_user_path(user_path, camp_roleid):
    if user_path and len(user_path) > 5:
        path = user_path.strip("/")
        return f"/{path}/"
    if camp_roleid:
        return f"/aovcamp/h5/user/{camp_roleid}/"
    return "/aovcamp/h5/user/default/"

def get_fresh_encodeparam(body_str="{}", roleid="", fallback_ep=None):
    auth = get_current_garena_auth()
    if not auth:
        return fallback_ep
    
    encryption = auth.get("encryption")
    camp_roleid = auth.get("camp_roleid", "")
    rid = roleid or camp_roleid
    
    if not encryption:
        return fallback_ep
        
    try:
        r = requests.post(f"{PROXY_URL}/get_signature", json={
            "encryption": encryption,
            "campRoleid": camp_roleid,
            "roleid": rid
        }, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("encodeparam"):
                return data.get("encodeparam")
    except Exception as e:
        log_to_web(f"Lỗi lấy chữ ký signature server: {str(e)[:60]}", "warning")
    return fallback_ep

def api_post(session, endpoint, payload, auth_token, encode_param=None, har_ua=None, har_sec_ch_ua=None, roleid="", retry_on_code1=False, max_retries=3, delay=3.0):
    hdrs = dict(FIXED_HEADERS)
    hdrs["content-type"]         = "application/json"
    hdrs["msdk-itopencodeparam"] = auth_token
    hdrs["traceparent"]          = gen_traceparent()
    hdrs["priority"]             = "u=1, i"
    hdrs["user-agent"]           = har_ua or "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    
    data = {}
    for attempt in range(max_retries):
        body_str = json.dumps(payload, separators=(',',':'))
        ep = get_fresh_encodeparam(body_str, roleid, encode_param)
        if ep:
            hdrs["encodeparam"] = ep
        hdrs["traceparent"] = gen_traceparent()
        try:
            r = session.post(API_BASE + endpoint, json=payload, headers=hdrs, timeout=25)
            try:
                data = r.json()
            except:
                data = {"code": -1, "msg": f"HTTP {r.status_code} - {r.text[:80]}"}
            if data is None:
                data = {"code": -1, "msg": "response body is null"}
            if r.status_code != 200:
                log_to_web(f"HTTP {r.status_code} trên {endpoint.split('/')[-1]} [{attempt+1}/{max_retries}]", "warning")
                if attempt < max_retries-1:
                    time.sleep(delay); continue
                return data
            if retry_on_code1 and data.get("code") == 1:
                wait = delay*(attempt+1)
                log_to_web(f"code=1 thử lại sau {int(wait)}s [{attempt+1}/{max_retries}]", "warning")
                time.sleep(wait); continue
            return data
        except Exception as e:
            log_to_web(f"Lỗi gửi API {endpoint}: {e}", "warning")
            if attempt < max_retries-1:
                time.sleep(delay); continue
            return {"code": -1, "msg": str(e)}
    return data

def _hmac_sha1(key, msg):
    return hmac_lib.new(key, msg.encode(), hashlib.sha1).hexdigest()

def build_cos_auth(sid, skey, method, pathname, clen):
    now   = int(time.time())
    end   = now + 86400
    kt    = "{};{}".format(now, end)
    sk    = _hmac_sha1(skey.encode(), kt)
    hh    = "content-length={}&host={}".format(clen, COS_HOST)
    hs    = "{}\n{}\n\n{}\n".format(method.lower(), pathname, hh)
    hhttp = hashlib.sha1(hs.encode()).hexdigest()
    s2s   = "sha1\n{}\n{}\n".format(kt, hhttp)
    sig   = _hmac_sha1(sk.encode(), s2s)
    return ("q-sign-algorithm=sha1&q-ak={}"
            "&q-sign-time={}&q-key-time={}"
            "&q-header-list=content-length;host&q-url-param-list="
            "&q-signature={}").format(sid, kt, kt, sig)

def cos_put(session, url, data, headers):
    for attempt in range(3):
        try:
            r = session.put(url, data=data, headers=headers, timeout=30)
            if r.status_code == 200:
                return r
        except Exception as e:
            log_to_web(f"Lỗi tải file lên COS: {e}", "warning")
        time.sleep(1.0)
    return None

def get_web_uses(roleid):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_uses.json")
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get(str(roleid), 0)
    except:
        return 0

def inc_web_uses(roleid):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_uses.json")
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except:
            pass
    roleid_str = str(roleid)
    data[roleid_str] = data.get(roleid_str, 0) + 1
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except:
        pass
    return data[roleid_str]

def report_web_ping(roleid, name, post_type):
    try:
        import threading
        def run():
            try:
                uses = get_web_uses(roleid)
                tool_type = "flowborn" if post_type == "image" else "loadtran"
                requests.get(
                    f"https://flowbron-bot.onrender.com/ping?did={roleid}&name={name}&type={tool_type}&uses={uses}",
                    timeout=5
                )
            except:
                pass
        threading.Thread(target=run, daemon=True).start()
    except:
        pass

# =============================================================================
# IMAGE RESIZER & COVER-CROP
# =============================================================================

def resize_to_poster(img_bytes, target_w, target_h, fit_mode="crop"):
    try:
        img = _PIL_Image.open(io.BytesIO(img_bytes))
        orig_w, orig_h = img.size
        orig_str = "{}x{}".format(orig_w, orig_h)

        resample = getattr(_PIL_Image, 'LANCZOS',
                           getattr(_PIL_Image.Resampling, 'LANCZOS', 1))

        if not target_w or not target_h:
            max_size = 1080
            if orig_w > max_size or orig_h > max_size:
                ratio = max_size / max(orig_w, orig_h)
                new_w = int(orig_w * ratio)
                new_h = int(orig_h * ratio)
                img = img.convert("RGBA").resize((new_w, new_h), resample)
                buf = io.BytesIO()
                img.save(buf, format="PNG", optimize=True)
                return buf.getvalue(), True, orig_str
            return img_bytes, False, orig_str

        if orig_w == target_w and orig_h == target_h and fit_mode == "crop":
            return img_bytes, False, orig_str

        if fit_mode == "crop":
            scale = max(target_w / orig_w, target_h / orig_h)
            new_w = int(orig_w * scale)
            new_h = int(orig_h * scale)
            img = img.convert("RGBA").resize((new_w, new_h), resample)
            
            left = (new_w - target_w) // 2
            top  = (new_h - target_h) // 2
            img = img.crop((left, top, left + target_w, top + target_h))
        else:
            # Fit modes (blur, white, black)
            ratio = min(target_w / orig_w, target_h / orig_h)
            fit_w = int(orig_w * ratio)
            fit_h = int(orig_h * ratio)
            img_fit = img.convert("RGBA").resize((fit_w, fit_h), resample)
            
            from PIL import ImageFilter
            if fit_mode == "blur":
                bg_scale = max(target_w / orig_w, target_h / orig_h)
                bg_w = int(orig_w * bg_scale)
                bg_h = int(orig_h * bg_scale)
                img_bg = img.convert("RGBA").resize((bg_w, bg_h), resample)
                
                bg_left = (bg_w - target_w) // 2
                bg_top = (bg_h - target_h) // 2
                img_bg = img_bg.crop((bg_left, bg_top, bg_left + target_w, bg_top + target_h))
                img_bg = img_bg.filter(ImageFilter.GaussianBlur(30))
            elif fit_mode == "white":
                img_bg = _PIL_Image.new("RGBA", (target_w, target_h), (255, 255, 255, 255))
            else:  # "black"
                img_bg = _PIL_Image.new("RGBA", (target_w, target_h), (0, 0, 0, 255))
                
            paste_x = (target_w - fit_w) // 2
            paste_y = (target_h - fit_h) // 2
            img_bg.paste(img_fit, (paste_x, paste_y), img_fit)
            img = img_bg

        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue(), True, orig_str
    except Exception as e:
        log_to_web(f"Lỗi resize ảnh: {e}", "warning")
        return img_bytes, False, "?"

BADGE_CONFIGS = {
    "0":  {"name": "Không dùng huy hiệu"},
    "1":  {"name": "SSS+ Tối Thượng",  "file": "sss+tt.png",     "pos": "center"},
    "2":  {"name": "SSS+ Hữu Hạn",     "file": "sss+hh.png",     "pos": "center"},
    "3":  {"name": "SSS Premium",      "file": "ssspre.png",     "pos": "center"},
    "4":  {"name": "SSS Hữu Hạn",      "file": "ssshh.png",      "pos": "center"},
    "5":  {"name": "SSS Giáp Thìn",    "file": "sssgt.png",      "pos": "center"},
    "6":  {"name": "SS Tuyệt Sắc",     "file": "ssts.png",       "pos": "center"},
    "7":  {"name": "SS Hữu Hạn",       "file": "sshh.png",       "pos": "center"},
    "8":  {"name": "SS Premium",       "file": "sspre.png",      "pos": "center"},
    "9":  {"name": "SS+ Premium",      "file": "ss+pre.png",     "pos": "center"},
    "10": {"name": "SS+ Hữu Hạn",      "file": "ss+hh.png",      "pos": "center"},
    "11": {"name": "SS Giáp Thìn",     "file": "ssgt.png",       "pos": "center"},
    "12": {"name": "SS VIP",           "file": "ssvip.png",      "pos": "center"},
    "13": {"name": "S+ Premium",       "file": "s+pre.png",      "pos": "center"},
    "14": {"name": "S+ Hữu Hạn",       "file": "s+hh.png",       "pos": "center"},
    "15": {"name": "S+ Giáp Thìn",     "file": "s+gt.png",       "pos": "center"},
    "16": {"name": "S Premium",        "file": "spre.png",       "pos": "center"},
    "17": {"name": "S Hữu Hạn",        "file": "shh.png",        "pos": "center"},
    "18": {"name": "S+ Bậc",           "file": "bacs+.png",      "pos": "center"},
    "19": {"name": "SS Bậc",           "file": "bacss.png",      "pos": "center"},
    "20": {"name": "S Bậc",            "file": "bacs.png",       "pos": "center"},
    "21": {"name": "A Bậc",            "file": "baca.png",       "pos": "center"},
    "22": {"name": "A VIP",            "file": "avip.png",       "pos": "center"},
    "23": {"name": "S+ Bính Ngọ",      "file": "s+binhngo.png",  "pos": "center"},
    "24": {"name": "SS Bính Ngọ",      "file": "ssbinhngo.png",  "pos": "center"},
    "25": {"name": "SS+ Bính Ngọ",     "file": "ss+binhngo.png", "pos": "center"},
}

def _find_badge_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "badges")

def composite_badge(png_bytes, badge_cfg, skin_name=None):
    from PIL import ImageDraw, ImageFont
    
    badge_file = badge_cfg.get("file") if badge_cfg else None
    has_badge = bool(badge_file)
    has_text  = bool(skin_name and skin_name.strip())

    if not has_badge and not has_text:
        return png_bytes

    img   = _PIL_Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    W, H  = img.size
    ov    = _PIL_Image.new("RGBA", (W, H), (0,0,0,0))

    badge_bottom_y = int(H * 0.55)

    if has_badge:
        badge_dir = _find_badge_dir()
        if badge_dir:
            badge_path = os.path.join(badge_dir, badge_file)
            if os.path.isfile(badge_path):
                badge = _PIL_Image.open(badge_path).convert("RGBA")
                bw = int(W * 0.75)
                ratio = bw / badge.width
                bh = int(badge.height * ratio)
                badge = badge.resize((bw, bh), getattr(_PIL_Image, 'LANCZOS', 1))

                bx, by = (W - bw) // 2, int(H * 0.48)
                ov.paste(badge, (bx, by), badge)
                badge_bottom_y = by + bh - int(bh * 0.30)

    if has_text:
        draw = ImageDraw.Draw(ov)
        _termux_prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
        _font_candidates = [
            r"C:\Windows\Fonts\segoeuib.ttf",
            r"C:\Windows\Fonts\arialbd.ttf",
            r"C:\Windows\Fonts\tahomabd.ttf",
            r"C:\Windows\Fonts\calibrib.ttf",
            "/system/fonts/NotoSansCJK-Bold.ttc",
            "/system/fonts/Roboto-Bold.ttf",
            "/system/fonts/NotoSansCJK-Regular.ttc",
            "/system/fonts/NotoSans-Regular.ttf",
            "/system/fonts/Roboto-Regular.ttf",
            "/system/fonts/DroidSans-Bold.ttf",
            "/system/fonts/DroidSans.ttf",
            os.path.join(_termux_prefix, "share/fonts/TTF/DejaVuSans-Bold.ttf"),
            os.path.join(_termux_prefix, "share/fonts/TTF/DejaVuSans.ttf"),
        ]
        font_size = max(20, int(H * 0.055))
        font = None
        for fp in _font_candidates:
            try:
                font = ImageFont.truetype(fp, font_size)
                break
            except Exception:
                pass
        if font is None:
            font = ImageFont.load_default()

        text = skin_name.strip()
        bb = draw.textbbox((0, 0), text, font=font)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        tx = (W - tw) // 2
        ty = badge_bottom_y

        try:
            draw.text((tx, ty), text, font=font,
                      fill=(255, 255, 255, 255),
                      stroke_width=max(2, int(font_size * 0.1)),
                      stroke_fill=(0, 0, 0, 230))
        except TypeError:
            ow = max(2, int(font_size * 0.08))
            for ox in range(-ow, ow+1):
                for oy in range(-ow, ow+1):
                    if ox*ox + oy*oy <= ow*ow:
                        draw.text((tx+ox, ty+oy), text, font=font, fill=(0,0,0,220))
            draw.text((tx, ty), text, font=font, fill=(255, 255, 255, 255))

    img = _PIL_Image.alpha_composite(img, ov)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="PNG")
    return buf.getvalue()

def prepare_media(file_bytes, filename, target_w, target_h, fit_mode="crop", badge_id="0", skin_name=""):
    ext = os.path.splitext(filename)[1].lower()
    raw = file_bytes

    if ext in (".jpg", ".jpeg", ".png", ".webp"):
        resized, did_resize, orig_size = resize_to_poster(raw, target_w, target_h, fit_mode)
        if did_resize:
            log_to_web(f"Tự chỉnh khung hình: {orig_size} -> {target_w}x{target_h}", "info")
            
        # Draw rank badge or skin name text if requested
        if badge_id and badge_id != "0":
            badge_cfg = BADGE_CONFIGS.get(badge_id)
            if badge_cfg:
                resized = composite_badge(resized, badge_cfg, skin_name)
        elif skin_name and skin_name.strip():
            resized = composite_badge(resized, None, skin_name)

        return {
            "png_bytes":  resized,
            "anim_bytes": None,
            "anim_ext":   None,
            "name":       filename,
        }

    if ext == ".gif":
        try:
            gif = _PIL_Image.open(io.BytesIO(raw))
            gif.seek(0)
            buf = io.BytesIO()
            gif.convert("RGBA").save(buf, format="PNG")
            png_b = buf.getvalue()
            png_b, did_resize, orig_size = resize_to_poster(png_b, target_w, target_h, fit_mode)
            if did_resize:
                log_to_web(f"Tự chỉnh GIF frame 1: {orig_size} -> {target_w}x{target_h}", "info")
                
            # Draw rank badge or skin name text on GIF thumbnail if requested
            if badge_id and badge_id != "0":
                badge_cfg = BADGE_CONFIGS.get(badge_id)
                if badge_cfg:
                    png_b = composite_badge(png_b, badge_cfg, skin_name)
            elif skin_name and skin_name.strip():
                png_b = composite_badge(png_b, None, skin_name)

            return {
                "png_bytes":  png_b,
                "anim_bytes": raw,
                "anim_ext":   "gif",
                "name":       filename,
            }
        except Exception as e:
            raise Exception("Lỗi xử lý file GIF: " + str(e))

    if ext == ".mp4":
        # Extract first frame using ffmpeg
        tmp_dir = os.environ.get("TMPDIR", tempfile.gettempdir())
        tmp_mp4 = os.path.join(tmp_dir, f"v4_tmp_{os.getpid()}.mp4")
        tmp_gif = os.path.join(tmp_dir, f"v4_tmp_{os.getpid()}.gif")
        tmp_png = os.path.join(tmp_dir, f"v4_tmp_{os.getpid()}.png")
        try:
            with open(tmp_mp4, "wb") as f:
                f.write(raw)
            log_to_web("Đang chuyển đổi định dạng MP4 -> GIF...", "info")
            subprocess.run(
                ["ffmpeg", "-i", tmp_mp4, "-vf", "fps=10,scale=320:-1:flags=lanczos", "-loop", "0", tmp_gif, "-y"],
                capture_output=True, check=True
            )
            with open(tmp_gif, "rb") as f:
                gif_b = f.read()
            subprocess.run(
                ["ffmpeg", "-i", tmp_gif, "-vframes", "1", "-f", "image2", tmp_png, "-y"],
                capture_output=True, check=True
            )
            with open(tmp_png, "rb") as f:
                png_b = f.read()
                
            for fp in [tmp_mp4, tmp_gif, tmp_png]:
                try: os.unlink(fp)
                except OSError: pass
                
            png_b, did_resize, orig_size = resize_to_poster(png_b, target_w, target_h)
            if did_resize:
                log_to_web(f"Tự chỉnh MP4 frame 1: {orig_size} -> {target_w}x{target_h}", "info")
                
            # Draw rank badge or skin name text on MP4 thumbnail if requested
            if badge_id and badge_id != "0":
                badge_cfg = BADGE_CONFIGS.get(badge_id)
                if badge_cfg:
                    png_b = composite_badge(png_b, badge_cfg, skin_name)
            elif skin_name and skin_name.strip():
                png_b = composite_badge(png_b, None, skin_name)

            return {
                "png_bytes":  png_b,
                "anim_bytes": gif_b,
                "anim_ext":   "gif",
                "name":       filename,
            }
        except Exception as e:
            raise Exception("Lỗi xử lý MP4 qua ffmpeg: " + str(e))

    raise Exception(f"Định dạng không hỗ trợ: {ext}")

# =============================================================================
# WEB FLASK ROUTES & AUTO LOGIN
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html', session_username=session.get("username"))

def find_local_browser():
    paths = [
        # Brave
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        # Chrome
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        # Edge
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None

@app.route('/api/login', methods=['GET'])
def auto_login():
    log_to_web("Phương pháp 1 đã bị Garena chặn phía máy chủ (lỗi login_invalid_grant_type). Vui lòng sử dụng PHƯƠNG PHÁP 2!", "error")
    return jsonify({
        "success": False, 
        "error": "Garena đã chặn cổng đăng nhập web. Vui lòng chuyển sang dùng PHƯƠNG PHÁP 2 (Lấy link từ game)!"
    })

def parse_har_bytes(raw_bytes):
    try:
        har = json.loads(raw_bytes.decode('utf-8', errors='ignore'))
    except Exception as e:
        raise Exception("Định dạng file HAR không hợp lệ (không phải JSON): " + str(e))
        
    auth_token    = None
    har_ua        = None
    har_sec_ch_ua = None
    user_path     = None
    main_job      = 5
    gender        = 2
    bi_raw        = {}

    for entry in har.get("log", {}).get("entries", []):
        if "getpostereditinfo" not in entry.get("request", {}).get("url", ""):
            continue
        try:
            body = json.loads(
                entry.get("response",{}).get("content",{}).get("text","{}"))
            bi = body.get("data",{}).get("picInfo",{}).get("baseInfo",{})
            if bi:
                main_job = int(bi.get("mainJob", main_job))
                gender   = int(bi.get("gender",  gender))
                bi_raw   = bi
        except Exception:
            pass

    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")

        # 1. Extract headers case-insensitively across ALL domains
        hdrs = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        
        # Check msdk-itopencodeparam or itopencodeparam in headers
        for k in ["msdk-itopencodeparam", "itopencodeparam"]:
            if k in hdrs and hdrs[k] and len(hdrs[k]) >= 32:
                auth_token = hdrs[k]
                break
                
        # 2. Extract from query string parameters
        if not auth_token:
            for q in req.get("queryString", []):
                qname = q.get("name", "").lower()
                if qname in ["msdk-itopencodeparam", "itopencodeparam"] and q.get("value") and len(q.get("value")) >= 32:
                    auth_token = q.get("value")
                    break

        if auth_token:
            if "user-agent" in hdrs and not har_ua:
                har_ua = hdrs["user-agent"]
            if "sec-ch-ua" in hdrs and not har_sec_ch_ua:
                har_sec_ch_ua = hdrs["sec-ch-ua"]

        if req.get("method") == "PUT" and "myqcloud.com" in url and not user_path:
            try:
                path  = url.split("myqcloud.com")[1].split("?")[0]
                parts = path.strip("/").split("/")
                if len(parts) >= 3:
                    user_path = "/" + "/".join(parts[:3]) + "/"
            except Exception:
                pass

        if not bi_raw and any(
            k in url for k in ("saveposter","savepostereditinfo")
        ):
            try:
                body = json.loads(req.get("postData",{}).get("text","{}"))
                bi   = body.get("picInfo",{}).get("baseInfo",{})
                if bi:
                    main_job = int(bi.get("mainJob", main_job))
                    gender   = int(bi.get("gender",  gender))
                    bi_raw   = bi
            except Exception:
                pass

    if not auth_token:
        # Fallback: scan raw bytes text with highly resilient regex patterns
        import re
        raw_text = raw_bytes.decode('utf-8', errors='ignore')
        
        # Pattern 1: JSON header format: "name":"msdk-itopencodeparam","value":"..."
        # Pattern 2: Standard parameter/header format: msdk-itopencodeparam=... or msdk-itopencodeparam: ...
        patterns = [
            r'(?:msdk-itopencodeparam|itopencodeparam)[\"\'\s]*,[\"\'\s]*\"value\"[\"\'\s]*:[\"\'\s]*\"([a-zA-Z0-9]{32,512})\"',
            r'(?:msdk-itopencodeparam|itopencodeparam)[\"\'\\\\\s]*[:=][\"\'\\\\\s]*([a-zA-Z0-9]{32,512})'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, raw_text, re.IGNORECASE)
            if matches:
                auth_token = matches[0]
                break
                
        if auth_token:
            # Try to grab user-agent and sec-ch-ua from headers
            for entry in har.get("log", {}).get("entries", []):
                req = entry.get("request", {})
                hdrs = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
                if "user-agent" in hdrs and not har_ua:
                    har_ua = hdrs["user-agent"]
                if "sec-ch-ua" in hdrs and not har_sec_ch_ua:
                    har_sec_ch_ua = hdrs["sec-ch-ua"]

    return auth_token, har_ua, har_sec_ch_ua, user_path, main_job, gender, bi_raw

@app.route('/api/upload_har', methods=['POST'])
def upload_har():
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "Không tìm thấy file!"})
        file = request.files['file']
        if not file.filename.endswith('.har'):
            return jsonify({"success": False, "error": "Vui lòng upload file định dạng .har!"})
            
        raw_bytes = file.read()
        log_to_web(f"Đang phân tích file HAR: {file.filename}...", "info")
        
        token, har_ua, har_sec_ch_ua, user_path, main_job, gender, bi_raw = parse_har_bytes(raw_bytes)
        
        if not token:
            return jsonify({"success": False, "error": "Không tìm thấy token 'msdk-itopencodeparam' trong file HAR!"})
            
        # Generate random traceparent
        import random
        rand_trace = f"00-{random.getrandbits(128):032x}-{random.getrandbits(64):016x}-01"
        
        ua = har_ua or "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
        
        # Verify token with Garena Camp API
        hdrs = {
            "content-type": "application/json",
            "msdk-itopencodeparam": token,
            "traceparent": rand_trace,
            "user-agent": ua,
            "cookie": "",
            "camp-source": "AOV-CAMP",
            "msdk-gameid": "1137",
            "camp-authtype": "msdk",
            "areaid": "1",
            "msdk-os": "1",
            "logicworldid": "1011",
            "aov-language": "VN",
            "msdk-channelid": "10",
            "aov-region": "1137",
            "origin": "https://kgvn-camp.mobagarena.com",
            "referer": "https://kgvn-camp.mobagarena.com/",
        }
        if har_sec_ch_ua:
            hdrs["sec-ch-ua"] = har_sec_ch_ua
            
        log_to_web("Đang xác thực Token từ file HAR...", "info")
        r = requests.post(
            "https://kgvn-api.mobagarena.com/api/user/game/getselfuserinfo",
            headers=hdrs,
            json={},
            timeout=15
        )
        res = r.json()
        if res.get("code") == 0:
            userdata = res.get("data", {})
            camp_roleid = userdata.get("role", {}).get("campRoleid", "")
            final_user_path = ensure_user_path(user_path or userdata.get("userPath", ""), camp_roleid)
            
            auth_data = {
                "auth_token": token,
                "traceparent": rand_trace,
                "cookie": "",
                "user_agent": ua,
                "encryption": userdata.get("encryption"),
                "camp_roleid": camp_roleid,
                "roleid": userdata.get("role", {}).get("roleid", ""),
                "user_path": final_user_path,
                "main_job": userdata.get("role", {}).get("mainJob", main_job),
                "gender": userdata.get("role", {}).get("gender", gender),
                "pic_info_raw": userdata.get("picInfo", {}),
                "name": userdata.get("role", {}).get("name", "Garena User")
            }
            if har_sec_ch_ua:
                auth_data["sec_ch_ua"] = har_sec_ch_ua
                
            username = session.get("username", "guest")
            _garena_auth_sessions[username] = auth_data
            log_to_web(f"Đăng nhập qua HAR thành công! Chào mừng {auth_data['name']}!", "success")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": f"Token trong HAR đã hết hạn (code: {res.get('code')})"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/submit_url', methods=['POST'])
def submit_url():
    try:
        data = request.json
        input_text = data.get('url', '').strip()
        if not input_text:
            return jsonify({"success": False, "error": "Vui lòng nhập URL hoặc Token!"})
            
        token = ""
        # 1. Parse token from URL or use directly
        if "msdk-itopencodeparam=" in input_text:
            token = input_text.split("msdk-itopencodeparam=")[1].split("&")[0].split("#")[0]
        elif "access_token=" in input_text:
            token = input_text.split("access_token=")[1].split("&")[0].split("#")[0]
        elif "itopencodeparam=" in input_text:
            token = input_text.split("itopencodeparam=")[1].split("&")[0].split("#")[0]
        elif "code=" in input_text:
            token = input_text.split("code=")[1].split("&")[0].split("#")[0]
        else:
            token = input_text
            
        if not token:
            return jsonify({"success": False, "error": "Không thể phân tích Token từ URL này!"})
            
        # Generate random traceparent
        import random
        rand_trace = f"00-{random.getrandbits(128):032x}-{random.getrandbits(64):016x}-01"
        
        # 2. Verify token with Garena Camp API
        hdrs = {
            "content-type": "application/json",
            "msdk-itopencodeparam": token,
            "traceparent": rand_trace,
            "user-agent": "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
            "cookie": "",
            "camp-source": "AOV-CAMP",
            "msdk-gameid": "1137",
            "camp-authtype": "msdk",
            "areaid": "1",
            "msdk-os": "1",
            "logicworldid": "1011",
            "aov-language": "VN",
            "msdk-channelid": "10",
            "aov-region": "1137",
            "origin": "https://kgvn-camp.mobagarena.com",
            "referer": "https://kgvn-camp.mobagarena.com/",
        }
        
        log_to_web("Đang xác thực Token với máy chủ Garena...", "info")
        r = requests.post(
            "https://kgvn-api.mobagarena.com/api/user/game/getselfuserinfo",
            headers=hdrs,
            json={},
            timeout=15
        )
        res = r.json()
        if res.get("code") == 0:
            userdata = res.get("data", {})
            camp_roleid = userdata.get("role", {}).get("campRoleid", "")
            final_user_path = ensure_user_path(userdata.get("userPath", ""), camp_roleid)
            auth_data = {
                "auth_token": token,
                "traceparent": rand_trace,
                "cookie": "",
                "user_agent": hdrs["user-agent"],
                "encryption": userdata.get("encryption"),
                "camp_roleid": camp_roleid,
                "roleid": userdata.get("role", {}).get("roleid", ""),
                "user_path": final_user_path,
                "main_job": userdata.get("role", {}).get("mainJob", 5),
                "gender": userdata.get("role", {}).get("gender", 2),
                "pic_info_raw": userdata.get("picInfo", {}),
                "name": userdata.get("role", {}).get("name", "Garena User")
            }
            username = session.get("username", "guest")
            _garena_auth_sessions[username] = auth_data
            log_to_web(f"Đăng nhập thành công! Chào mừng {auth_data['name']}!", "success")
            report_web_ping(auth_data["roleid"], auth_data["name"], "image")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": f"Garena từ chối token (code: {res.get('code')}, msg: {res.get('message')})"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# =============================================================================
# UPLOAD AND POST WORKER
# =============================================================================

def background_post_worker(auth, post_type, title, content, file_bytes, filename, main_job=None, gender=None, fit_mode="crop", layout_preset="2", badge_id="0", skin_name="", aspect_ratio="vertical"):
    session = requests.Session()
    
    # Configure dimensions
    if post_type == "video": # LoadTran mode
        target_w = 1080
        target_h = 1701
    else: # Poster / custom aspect ratio
        if aspect_ratio == "original":
            target_w = None
            target_h = None
        elif aspect_ratio == "horizontal":
            target_w = 960
            target_h = 540
        elif aspect_ratio == "square":
            target_w = 600
            target_h = 600
        else: # "vertical"
            target_w = 512
            target_h = 666
    
    log_to_web(f"Bắt đầu chuẩn bị media ({filename})...", "info")
    try:
        media = prepare_media(file_bytes, filename, target_w, target_h, fit_mode, badge_id, skin_name)
    except Exception as e:
        log_to_web(f"Lỗi chuẩn bị media: {e}", "error")
        return

    png_b = media["png_bytes"]
    anim_b = media["anim_bytes"]
    anim_ext = media["anim_ext"]
    
    try:
        # A. Createposter
        log_to_web("Đang tạo phiên đăng bài (createposter)...", "info")
        endpoint_create = "/api/game/poster/flowborn/createposter" if post_type == "image" else "/api/game/poster/playerimage/createposter"
        r = api_post(session, endpoint_create, {}, auth["auth_token"], roleid=auth["roleid"])
        
        if r.get("code") != 0:
            log_to_web(f"Createposter lỗi: {r.get('msg')}", "error")
            return
            
        pid = r["data"]["posterId"]
        log_to_web(f"Tạo poster thành công, ID = {pid}", "success")
        time.sleep(0.5)

        # B. COS credentials
        def get_cos_creds(fname_short):
            scene = "FlowbornPoster" if post_type == "image" else "PlayerimagePoster"
            rc = api_post(session, "/api/game/poster/getcoscredential",
                          {"scene": scene, "fileName": fname_short},
                          auth["auth_token"], roleid=auth["roleid"])
            if rc.get("code") != 0:
                log_to_web(f"Lấy COS Credentials thất bại: {rc.get('msg')}", "error")
                return None
            return rc.get("data")

        def mkhdr(crd, key, buf, ct):
            return {
                "Authorization":        build_cos_auth(crd["tmpSecretId"], crd["tmpSecretKey"], "PUT", key, len(buf)),
                "Content-Type":         ct,
                "Content-Length":       str(len(buf)),
                "Host":                 COS_HOST,
                "x-cos-security-token": crd["token"],
                "Origin":               "https://kgvn-camp.mobagarena.com",
                "Referer":              "https://kgvn-camp.mobagarena.com/",
            }

        # Setup paths
        selected_job = main_job or auth["main_job"]
        selected_gender = gender or auth["gender"]
        
        path_png = f"{selected_job}/1/{pid}.png" if post_type == "image" else f"0/1/{pid}.png"
        path_large = f"{selected_job}/1/{pid}_large.png" if post_type == "image" else f"0/1/{pid}_large.png"

        # Fetch large credentials first to dynamically resolve user_path
        log_to_web("Đang tải ảnh cỡ lớn lên COS...", "info")
        creds_l = get_cos_creds(path_large)
        if not creds_l: return
        
        # Dynamically extract user_path from creds_l["path"]
        cos_path_full = creds_l.get("path", "")
        if cos_path_full and path_large in cos_path_full:
            user_path = cos_path_full.split(path_large)[0]
        else:
            user_path = auth["user_path"]
            
        ck = user_path + path_png
        ck_l = user_path + path_large

        # Upload Large image
        r_l = cos_put(session, "https://" + COS_HOST + ck_l, png_b, mkhdr(creds_l, ck_l, png_b, "image/png"))
        if r_l and r_l.status_code == 200:
            log_to_web("Tải ảnh cỡ lớn thành công!", "success")
        time.sleep(0.3)

        # Upload Normal image
        log_to_web("Đang tải ảnh chuẩn lên COS...", "info")
        creds_p = get_cos_creds(path_png)
        if not creds_p: return
        r_p = cos_put(session, "https://" + COS_HOST + ck, png_b, mkhdr(creds_p, ck, png_b, "image/jpeg"))
        if r_p and r_p.status_code == 200:
            log_to_web("Tải ảnh chuẩn thành công!", "success")
        
        sticker_url = CDN_BASE + ck
        time.sleep(0.3)

        # Upload dynamic animation (GIF/MP4)
        if anim_b and anim_ext:
            path_anim = f"{main_job}/1/{pid}.{anim_ext}" if post_type == "image" else f"0/1/{pid}.{anim_ext}"
            ck_a = user_path + path_anim
            log_to_web(f"Đang tải ảnh động .{anim_ext} lên COS...", "info")
            creds_a = get_cos_creds(path_anim)
            if creds_a:
                r_a = cos_put(session, "https://" + COS_HOST + ck_a, anim_b, mkhdr(creds_a, ck_a, anim_b, "image/png"))
                if r_a and r_a.status_code == 200:
                    sticker_url = CDN_BASE + ck_a
                    log_to_web(f"Tải tệp động .{anim_ext} thành công!", "success")
            time.sleep(0.3)

        # C. savepostereditinfo & saveposter
        log_to_web("Đang hoàn tất cấu trúc bài viết (editInfo)...", "info")
        pic_info_raw = auth["pic_info_raw"]
        
        if post_type == "image":
            # Flowborn Poster Payload
            bpi = pic_info_raw.get("baseInfo") or {}
            cfg = ROLE_CONFIGS.get((selected_job, selected_gender), {"id": 32, "picUrl": "https://kg-camp.mobagarena.com/manage/flowborn_official/Pd7zTH2f.png"})
            bi = {
                "id": str(cfg["id"]),
                "gender": int(selected_gender),
                "mainJob": int(selected_job),
                "picUrl": cfg["picUrl"],
                "skinColor": 1,
            }
            sp = STICKER_PRESETS.get(layout_preset, STICKER_PRESETS["2"])
            pi = {
                "bg": {
                    "id": pic_info_raw.get("bg", {}).get("id", "30"),
                    "picUrl": pic_info_raw.get("bg", {}).get("picUrl", CDN_OFFICIAL + "/manage/flowborn_official/4uxOQChv.png")
                },
                "baseInfo": bi,
                "stickerList": [{
                    "id": "190",
                    "picUrl": sticker_url,
                    "width": sp["width"], "height": sp["height"],
                    "posX": sp["posX"], "posY": sp["posY"],
                    "rotate": 0, "source": 1, "type": 1,
                }]
            }
            endpoint_edit = "/api/game/poster/flowborn/savepostereditinfo"
            endpoint_save = "/api/game/poster/flowborn/saveposter"
            payload_edit = {"mainJob": selected_job, "picInfo": pi}
            payload_save = {
                "posterId": pid,
                "isApply": True,
                "isShare": True,
                "mainJob": selected_job,
                "picUrl": CDN_BASE + user_path,
                "picInfo": pi
            }
        else:
            # LoadTran Poster Payload
            bg = pic_info_raw.get("bg", {})
            pi = {
                "bg": {
                    "id": bg.get("id", PI_BG_ID),
                    "picUrl": bg.get("picUrl", PI_BG_PICURL),
                    "source": 1,
                    "width": bg.get("width", PI_BG_W),
                    "height": bg.get("height", PI_BG_H),
                    "posX": bg.get("posX", 0),
                    "posY": bg.get("posY", 0),
                },
                "stickerList": [],
            }
            endpoint_edit = "/api/game/poster/playerimage/savepostereditinfo"
            endpoint_save = "/api/game/poster/playerimage/saveposter"
            payload_edit = {"picInfo": pi}
            payload_save = {
                "posterId": pid, "isApply": True, "isShare": True,
                "picUrl": CDN_BASE + user_path, "picInfo": pi
            }

        # Post editInfo
        rs = api_post(session, endpoint_edit, payload_edit, auth["auth_token"], roleid=auth["roleid"], retry_on_code1=True)
        if rs.get("code") != 0:
            log_to_web(f"Lưu editInfo thất bại: {rs.get('msg')}", "error")
            return
        time.sleep(1.0)

        # Post saveposter
        rp = api_post(session, endpoint_save, payload_save, auth["auth_token"], roleid=auth["roleid"], retry_on_code1=True)
        if rp.get("code") == 0:
            log_to_web(f"ĐĂNG BÀI VIẾT THÀNH CÔNG! ID: {pid}", "success")
            inc_web_uses(auth["roleid"])
            report_web_ping(auth["roleid"], auth["name"], post_type)
        else:
            log_to_web(f"Lưu bài đăng thất bại: {rp.get('msg')}", "error")

    except Exception as e:
        log_to_web(f"Lỗi tiến trình đăng bài: {e}", "error")

@app.route('/api/upload_image', methods=['POST'])
def upload_image():
    auth = get_current_garena_auth()
    if not auth:
        return jsonify({"error": "Chưa đăng nhập!"}), 403
        
    post_type = request.form.get('postType', 'image')
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    file = request.files.get('file')
    
    if not file:
        return jsonify({"error": "Không có tệp tải lên!"}), 400
        
    file_bytes = file.read()
    filename = file.filename
    
    main_job = request.form.get('mainJob')
    gender = request.form.get('gender')
    fit_mode = request.form.get('fitMode', 'crop')
    layout_preset = request.form.get('layoutPreset', '2')
    badge_id = request.form.get('badgeId', '0')
    skin_name = request.form.get('skinName', '')
    aspect_ratio = request.form.get('aspectRatio', 'vertical')
    if main_job: main_job = int(main_job)
    if gender: gender = int(gender)
    
    # Start posting worker thread to process in background
    threading.Thread(
        target=background_post_worker,
        args=(auth, post_type, title, content, file_bytes, filename, main_job, gender, fit_mode, layout_preset, badge_id, skin_name, aspect_ratio),
        daemon=True
    ).start()
    
    return jsonify({"success": True, "msg": "Đang tiến hành xử lý đăng bài..."})

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get("username", "guest")
    _garena_auth_sessions.pop(username, None)
    return jsonify({"success": True})

@app.route('/api/user_status', methods=['GET'])
def user_status():
    auth = get_current_garena_auth()
    if auth:
        return jsonify({
            "logged_in": True,
            "name": auth.get("name", "Garena User")
        })
    return jsonify({"logged_in": False})


# =============================================================================
# BROWSER & APP STARTUP
# =============================================================================

def start_browser():
    import time
    time.sleep(1.5)
    webbrowser.open('http://127.0.0.1:8080')

if __name__ == '__main__':
    print("Khởi động Giao diện Web Flowborn V4...")
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8080))
    if host == "127.0.0.1" or host == "localhost":
        threading.Thread(target=start_browser, daemon=True).start()
    app.run(host=host, port=port)
