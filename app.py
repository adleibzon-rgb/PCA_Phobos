#!/usr/bin/env python3
"""
PCA Phobos — Web Panel for Phobos (Obfuscated WireGuard VPN)
Management panel: clients, sessions, labels, subscriptions, Telegram alerts.
"""

import json, os, subprocess, threading, time, secrets, hashlib, re, fcntl, hmac, ipaddress
import html as html_lib
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, make_response, send_from_directory
try:
    from flask_sock import Sock
except Exception:
    Sock = None

_settings_lock = threading.Lock()

app = Flask(__name__)
# ttyd clients require the server to select the 'tty' subprotocol; simple_websocket
# only echoes it when the client requested it, so SSH-terminal WS (no subprotocol)
# is unaffected.
app.config["SOCK_SERVER_OPTIONS"] = {"subprotocols": ["tty"]}
sock = Sock(app) if Sock else None
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

PHOBOS_DIR = "/opt/Phobos"
CLIENTS_DIR = f"{PHOBOS_DIR}/clients"
SERVER_ENV = f"{PHOBOS_DIR}/server/server.env"
PANEL_DIR = "/opt/phobos-panel"
SETTINGS_FILE = f"{PANEL_DIR}/settings.json"
SECRET_FILE = f"{PANEL_DIR}/.secret_key"
WG_CONFIG = "/etc/wireguard/wg0.conf"
# Distribution: Gitea first (GitHub account is unavailable since 23.10.2026), GitHub fallback
PCA_GIT = "https://git.bobyrev.com/PCA/PCA_Phobos"
PCA_GH_RAW = "https://raw.githubusercontent.com/andrey271192/PCA_Phobos"
APK_TAG = "v1.4.0"
WARP_DIR = f"{PHOBOS_DIR}/server/warp"
WARP_CUSTOM_PROFILE_FILE = f"{WARP_DIR}/custom-profile.conf"
WARP_LICENSE_FILE = f"{WARP_DIR}/license.key"
SERVER_IP = subprocess.getoutput("curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}'").strip()

os.makedirs(PANEL_DIR, exist_ok=True)

if os.path.exists(SECRET_FILE):
    app.secret_key = open(SECRET_FILE).read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(app.secret_key)

DEFAULT_SETTINGS = {
    "admin_pass": "OcAdmin2026!",
    "tg_bot_token": "",
    "tg_chat_id": "",
    "monitor_interval": 30,
    "labels": {},
    "subscriptions": {},
    "warp": {
        "mode": "egress",
        "profile_source": "free",
        "relay_ports": "4500",
        "relay_target": "",
        "license_key": "",
    },
    "warp_clients": [],
    "client_aliases": {},
    "obf_params": {
        "masking": "AUTO",
        "max_dummy": "4",
        "idle": "300",
    },
}
LOGIN_ATTEMPTS = {}
LOGIN_WINDOW = 900
LOGIN_MAX_ATTEMPTS = 10


def load_settings():
    with _settings_lock:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE) as f:
                s = json.load(f)
            for k, v in DEFAULT_SETTINGS.items():
                s.setdefault(k, v)
            if not s.get("server_api_key"):
                s["server_api_key"] = secrets.token_hex(16)
                with open(SETTINGS_FILE, "w") as f:
                    json.dump(s, f, indent=2, ensure_ascii=False)
            return s
        s = dict(DEFAULT_SETTINGS)
        s["server_api_key"] = secrets.token_hex(16)
        return s


def save_settings(s):
    with _settings_lock:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(s, f, indent=2, ensure_ascii=False)


def _load_server_env():
    """Load server.env as dict for subprocess env."""
    env = {}
    if os.path.exists(SERVER_ENV):
        with open(SERVER_ENV) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k] = v
    return env


def _server_wg_interface():
    env = _load_server_env()
    iface = (env.get("SERVER_WG_IPV4_ADDRESS") or "").strip()
    if iface:
        return iface
    try:
        if os.path.exists("/etc/wireguard/wg0.conf"):
            with open("/etc/wireguard/wg0.conf") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if raw.startswith("Address"):
                        value = raw.split("=", 1)[1].split(",", 1)[0].strip()
                        if value:
                            return value
    except Exception:
        pass
    net = (env.get("SERVER_WG_IPV4_NETWORK") or "10.25.0.0/16").strip()
    try:
        network = ipaddress.ip_network(net, strict=False)
        return str(ipaddress.ip_interface(f"{next(network.hosts())}/{network.prefixlen}"))
    except Exception:
        return "10.25.0.1/16"


def server_wg_network():
    env = _load_server_env()
    raw = (env.get("SERVER_WG_IPV4_NETWORK") or "").strip()
    if raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except Exception:
            pass
    try:
        return str(ipaddress.ip_interface(_server_wg_interface()).network)
    except Exception:
        return "10.25.0.0/16"


def server_tunnel_ip():
    try:
        return str(ipaddress.ip_interface(_server_wg_interface()).ip)
    except Exception:
        return "10.25.0.1"


def client_display_name(cid, s=None):
    cid = str(cid or "").strip()
    aliases = (s or load_settings()).get("client_aliases", {}) or {}
    alias = str(aliases.get(cid, "") or "").strip()
    return alias or cid


def panel_service_name():
    for name in ("phobos-dev-test", "phobos-panel"):
        try:
            r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
            if (r.stdout or "").strip() in ("active", "inactive", "failed", "activating", "deactivating"):
                return name
        except Exception:
            pass
    return "phobos-panel"


def login_allowed(ip):
    now = int(time.time())
    rec = [ts for ts in LOGIN_ATTEMPTS.get(ip, []) if now - ts < LOGIN_WINDOW]
    LOGIN_ATTEMPTS[ip] = rec
    return len(rec) < LOGIN_MAX_ATTEMPTS


def login_failed(ip):
    now = int(time.time())
    rec = [ts for ts in LOGIN_ATTEMPTS.get(ip, []) if now - ts < LOGIN_WINDOW]
    rec.append(now)
    LOGIN_ATTEMPTS[ip] = rec


def login_reset(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


def _default_warp_settings():
    return dict(DEFAULT_SETTINGS["warp"])


def get_warp_settings(s=None):
    src = (s or load_settings()).get("warp", {})
    out = _default_warp_settings()
    if isinstance(src, dict):
        out.update({k: str(v) for k, v in src.items() if v is not None})
    out["mode"] = out.get("mode", "egress") if out.get("mode", "egress") in ("egress", "relay") else "egress"
    out["profile_source"] = out.get("profile_source", "free") if out.get("profile_source", "free") in ("free", "custom") else "free"
    out["relay_ports"] = out.get("relay_ports", "4500").strip() or "4500"
    out["relay_target"] = out.get("relay_target", "").strip()
    out["license_key"] = out.get("license_key", "").strip()
    return out


def read_custom_warp_profile():
    try:
        return Path(WARP_CUSTOM_PROFILE_FILE).read_text()
    except Exception:
        return ""


def save_custom_warp_profile(text):
    text = (text or "").strip()
    os.makedirs(WARP_DIR, exist_ok=True)
    Path(WARP_CUSTOM_PROFILE_FILE).write_text(text + ("\n" if text else ""))
    return True


def read_warp_license_key():
    try:
        return Path(WARP_LICENSE_FILE).read_text().strip()
    except Exception:
        return ""


def save_warp_license_key(text):
    text = (text or "").strip()
    os.makedirs(WARP_DIR, exist_ok=True)
    Path(WARP_LICENSE_FILE).write_text(text + ("\n" if text else ""))
    return True


def delete_warp_license_key():
    try:
        os.remove(WARP_LICENSE_FILE)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def delete_custom_warp_profile():
    try:
        os.remove(WARP_CUSTOM_PROFILE_FILE)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def tg_send(text):
    s = load_settings()
    token, chat = s.get("tg_bot_token", ""), s.get("tg_chat_id", "")
    if not token or not chat:
        return
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = json.dumps({"chat_id": chat, "text": text, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def notify_on(cid):
    return load_settings().get("client_notify", {}).get(cid, True)


def warp_clients_enabled():
    vals = load_settings().get("warp_clients", [])
    return {str(x).strip() for x in vals if str(x).strip()}


def client_warp_enabled(cid):
    return cid in warp_clients_enabled()


def client_script_path():
    return f"{PHOBOS_DIR}/repo/server/scripts/phobos-client.sh"


def create_client_cli(name):
    """Create a client (add + assign + fanout + install link). Returns (ok, html_msg). Used by web + Telegram bot."""
    import re as _re
    name = (name or "").strip()
    cid = _normalize_client_id(name)
    if not name or not _re.match(r"^[a-zA-Z0-9_-]+$", name):
        return False, "Имя: латиница, цифры, _ и - (без пробелов)."
    if os.path.isdir(os.path.join(CLIENTS_DIR, cid)):
        return False, "Клиент %s уже существует." % cid
    script = client_script_path()
    try:
        subprocess.check_output([script, "add", name], text=True, timeout=45,
                                stderr=subprocess.STDOUT, env={**os.environ, **_load_server_env()})
    except subprocess.CalledProcessError as e:
        return False, "Ошибка создания: %s" % (e.output or "")[-300:]
    try:
        auto_assign_server(cid); fanout_router_config(cid)
    except Exception:
        pass
    cmd = ""
    try:
        out = subprocess.check_output([script, "link", name], text=True, timeout=25,
                                      stderr=subprocess.STDOUT, env={**os.environ, **_load_server_env()})
        for ln in out.splitlines():
            if ln.strip().startswith("curl") or "/init/" in ln:
                cmd = ln.strip(); break
    except Exception:
        pass
    msg = "\u2705 Клиент <b>%s</b> создан." % cid
    if cmd:
        msg += "\n\nКоманда установки на роутер:\n<code>%s</code>" % cmd
    return True, msg


def delete_client_cli(cid):
    cid = (cid or "").strip()
    if not cid or not os.path.isdir(os.path.join(CLIENTS_DIR, cid)):
        return False, "Клиент %s не найден." % cid
    script = client_script_path()
    try:
        subprocess.check_output([script, "remove", cid], text=True, timeout=25,
                                stderr=subprocess.STDOUT, env={**os.environ, **_load_server_env()})
    except subprocess.CalledProcessError as e:
        return False, "Ошибка удаления: %s" % (e.output or "")[-300:]
    try:
        st = load_settings()
        st.get("client_assignments", {}).pop(cid, None)
        st.get("client_notify", {}).pop(cid, None)
        save_settings(st)
    except Exception:
        pass
    return True, "\U0001F5D1 Клиент <b>%s</b> удалён." % cid


def tg_api(method, payload, token=None):
    import urllib.request
    if token is None:
        token = load_settings().get("tg_bot_token", "")
    if not token:
        return None
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request("https://api.telegram.org/bot%s/%s" % (token, method),
                                     data=data, headers={"Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except Exception:
        return None


MAIN_KB = {
    "keyboard": [
        ["➕ Создать клиента", "\U0001F4CB Список"],
        ["\U0001F5D1 Удалить", "\U0001F4CA Статус"],
        ["❓ Помощь"],
    ],
    "resize_keyboard": True,
}

_bot_state = {}


def _bot_status_text():
    servers = [{"ip": SERVER_IP, "is_primary": True}] + load_servers()
    lines = ["\U0001F4CA <b>Серверы</b>:"]
    for sv in servers:
        ip = sv.get("ip", "")
        st = "ok" if ip == SERVER_IP else server_stats_cache.get(ip, {}).get("status", "?")
        emoji = "\U0001F7E2" if st == "ok" else ("\U0001F534" if st == "down" else "⚪")
        lines.append("%s %s%s" % (emoji, ip, " (primary)" if sv.get("is_primary") else ""))
    online = set()
    try:
        for p, info in get_wg_peers().items():
            if is_peer_online(info.get("latest handshake", "")):
                online.add(p)
        for _ip, hs in server_handshakes_cache.items():
            for p, tsv in hs.items():
                if tsv and (time.time() - tsv) < 180:
                    online.add(p)
    except Exception:
        pass
    lines.append("\n\U0001F4F1 <b>Клиенты</b>:")
    cl = get_clients()
    if not cl:
        lines.append("нет")
    for c in cl:
        on = c.get("public_key", "") in online
        lines.append(("\U0001F7E2 " if on else "⚪ ") + c.get("client_id", ""))
    return "\n".join(lines)


def qr_png_bytes(data):
    import qrcode, io
    buf = io.BytesIO(); qrcode.make(data).save(buf, format="PNG"); return buf.getvalue()


def tg_send_photo(chat, png, caption=""):
    import urllib.request, secrets as _sec
    token = load_settings().get("tg_bot_token", "")
    if not token:
        return None
    boundary = "----phobos" + _sec.token_hex(8)
    def fld(name, val):
        return ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (boundary, name, val)).encode()
    body = fld("chat_id", str(chat)) + fld("caption", caption) + fld("parse_mode", "HTML")
    body += ("--%s\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"qr.png\"\r\nContent-Type: image/png\r\n\r\n" % boundary).encode()
    body += png + ("\r\n--%s--\r\n" % boundary).encode()
    try:
        req = urllib.request.Request("https://api.telegram.org/bot%s/sendPhoto" % token, data=body,
                                     headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
        return urllib.request.urlopen(req, timeout=25).read()
    except Exception:
        return None


def bot_send_new_client(chat, name):
    ok, rep = create_client_cli(name)
    tg_api("sendMessage", {"chat_id": chat, "text": rep, "parse_mode": "HTML", "reply_markup": MAIN_KB})
    if ok:
        try:
            conf, link = build_phone_config(name, "android")
            if link:
                tg_send_photo(chat, qr_png_bytes(link), "📱 Android (PhobosWG) — отсканируй QR в приложении")
                tg_api("sendMessage", {"chat_id": chat, "text": "phobos:// ссылка (Android):\n<code>%s</code>" % link, "parse_mode": "HTML"})
        except Exception:
            pass


def telegram_bot():
    offset = 0
    import urllib.request
    while True:
        try:
            s = load_settings()
            token = s.get("tg_bot_token", "")
            chat = str(s.get("tg_chat_id", ""))
            if not token or not chat:
                time.sleep(15); continue
            url = "https://api.telegram.org/bot%s/getUpdates?timeout=30&offset=%d" % (token, offset)
            data = json.loads(urllib.request.urlopen(url, timeout=40).read())
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                cq = upd.get("callback_query")
                if cq:
                    if str(cq.get("message", {}).get("chat", {}).get("id", "")) != chat:
                        continue
                    cdata = cq.get("data", "")
                    if cdata.startswith("del:"):
                        _, rep = delete_client_cli(cdata[4:])
                        tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": "OK"})
                        tg_api("sendMessage", {"chat_id": chat, "text": rep, "parse_mode": "HTML", "reply_markup": MAIN_KB})
                    continue
                m = upd.get("message") or upd.get("channel_post")
                if not m:
                    continue
                if str(m.get("chat", {}).get("id", "")) != chat:
                    continue
                text = (m.get("text") or "").strip()
                if not text:
                    continue
                # detect reply-keyboard button by its emoji prefix (NOT a command/arg)
                btn = None
                if not text.startswith("/"):
                    if text.startswith("➕"):
                        btn = "add"
                    elif text.startswith("\U0001F5D1"):
                        btn = "del"
                    elif text.startswith("\U0001F4CB"):
                        btn = "list"
                    elif text.startswith("\U0001F4CA"):
                        btn = "status"
                    elif text.startswith("❓"):
                        btn = "help"
                # conversation: awaiting a client name to create
                if _bot_state.get(chat) == "add":
                    if btn is None and not text.startswith("/"):
                        _bot_state.pop(chat, None)
                        bot_send_new_client(chat, text)
                        continue
                    _bot_state.pop(chat, None)  # a button/command cancels the prompt
                # parse slash command + arg (buttons carry no arg)
                cmd = ""
                arg = ""
                if text.startswith("/"):
                    toks = text.split()
                    cmd = toks[0].split("@")[0].lower()
                    arg = toks[1] if len(toks) > 1 else ""
                if btn == "add" or cmd in ("/add", "/new", "/create"):
                    if arg:
                        bot_send_new_client(chat, arg)
                    else:
                        _bot_state[chat] = "add"
                        tg_api("sendMessage", {"chat_id": chat, "text": "Введите имя нового клиента (латиница, цифры, _ и -):"})
                elif btn == "del" or cmd in ("/del", "/delete", "/remove", "/rm"):
                    if arg:
                        _, rep = delete_client_cli(arg)
                        tg_api("sendMessage", {"chat_id": chat, "text": rep, "parse_mode": "HTML", "reply_markup": MAIN_KB})
                    else:
                        cl = get_clients()
                        if not cl:
                            tg_api("sendMessage", {"chat_id": chat, "text": "Клиентов нет.", "reply_markup": MAIN_KB})
                        else:
                            kb = {"inline_keyboard": [[{"text": "\U0001F5D1 " + c.get("client_id", ""), "callback_data": "del:" + c.get("client_id", "")}] for c in cl]}
                            tg_api("sendMessage", {"chat_id": chat, "text": "Кого удалить? Нажми на клиента:", "reply_markup": kb})
                elif btn == "list" or cmd in ("/list", "/ls"):
                    cl = [c.get("client_id", "") for c in get_clients()]
                    rep = ("Клиенты (%d):\n" % len(cl)) + "\n".join("• " + c for c in cl) if cl else "Клиентов нет."
                    tg_api("sendMessage", {"chat_id": chat, "text": rep, "reply_markup": MAIN_KB})
                elif btn == "status" or cmd in ("/status", "/stat"):
                    tg_api("sendMessage", {"chat_id": chat, "text": _bot_status_text(), "parse_mode": "HTML", "reply_markup": MAIN_KB})
                elif btn == "help" or cmd in ("/help", "/start"):
                    rep = ("<b>PCA Phobos — бот</b>\n\n"
                           "Кнопки внизу или команды:\n"
                           "➕ /add &lt;имя&gt; — создать клиента\n"
                           "\U0001F5D1 /del &lt;имя&gt; — удалить\n"
                           "\U0001F4CB /list — список\n"
                           "\U0001F4CA /status — статус")
                    tg_api("sendMessage", {"chat_id": chat, "text": rep, "parse_mode": "HTML", "reply_markup": MAIN_KB})
        except Exception:
            time.sleep(10)

def get_wg_peers():
    """Parse `wg show wg0` to get active peers with transfer/handshake info."""
    try:
        out = subprocess.check_output(["wg", "show", "wg0"], text=True, timeout=5)
    except Exception:
        return {}

    peers = {}
    current_pub = None
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("peer:"):
            current_pub = line.split("peer:")[1].strip()
            peers[current_pub] = {}
        elif current_pub and ":" in line:
            key, val = line.split(":", 1)
            peers[current_pub][key.strip()] = val.strip()
    return peers


def get_wg_allowed_ips():
    try:
        out = subprocess.check_output(["wg", "show", "wg0", "allowed-ips"], text=True, timeout=5)
    except Exception:
        return {}
    data = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            data[parts[0].strip()] = parts[1].strip()
    return data


def _orphan_client_id(tunnel_ip):
    tip = (tunnel_ip or "").split("/")[0].strip() or "unknown"
    return "orphan-" + re.sub(r"[^a-zA-Z0-9]+", "-", tip).strip("-")


def get_clients(include_orphans=False):
    """Read all clients from /opt/Phobos/clients/*/metadata.json."""
    clients = []
    clients_path = Path(CLIENTS_DIR)
    if not clients_path.exists():
        clients_path = None
    if clients_path:
        for d in sorted(clients_path.iterdir()):
            meta_file = d / "metadata.json"
            if meta_file.exists():
                try:
                    with open(meta_file) as f:
                        meta = json.load(f)
                    meta["_dir"] = str(d)
                    clients.append(meta)
                except Exception:
                    pass
    if include_orphans:
        known = {c.get("public_key", ""): c for c in clients if c.get("public_key", "")}
        allowed = get_wg_allowed_ips()
        for pub, ip in allowed.items():
            if pub in known:
                continue
            tip = (ip or "").split(",")[0].strip()
            clients.append({
                "client_id": _orphan_client_id(tip),
                "client_name": _orphan_client_id(tip),
                "tunnel_ip_v4": tip,
                "public_key": pub,
                "created_at": "",
                "_orphan": True,
            })
    return clients


def purge_orphan_peer(public_key):
    pub = (public_key or "").strip()
    if not pub:
        return False, "empty public key"
    try:
        subprocess.run(["wg", "set", "wg0", "peer", pub, "remove"], check=True, timeout=5)
    except Exception as e:
        return False, f"wg remove failed: {e}"
    try:
        cfg = Path(WG_CONFIG)
        if cfg.exists():
            text = cfg.read_text()
            blocks = [b for b in re.split(r"\n\s*\n", text.strip()) if b.strip()]
            kept = []
            for block in blocks:
                if pub in block and "[Peer]" in block:
                    continue
                kept.append(block)
            cfg.write_text("\n\n".join(kept).strip() + "\n")
    except Exception:
        pass
    return True, f"orphan peer removed: {pub[:12]}..."


def get_active_sessions():
    """Combine WG peers with client metadata to build session list."""
    peers = get_wg_peers()
    clients = get_clients(include_orphans=True)

    pub_to_client = {}
    for c in clients:
        pub_to_client[c.get("public_key", "")] = c

    sessions = []
    for pub_key, info in peers.items():
        handshake = info.get("latest handshake", "")
        if not handshake:
            continue

        client = pub_to_client.get(pub_key, {})
        client_id = client.get("client_id", "unknown")
        tunnel_ip = client.get("tunnel_ip_v4", "")

        endpoint = info.get("endpoint", "")
        real_ip = endpoint.split(":")[0] if endpoint else ""

        rx = info.get("transfer", "")
        rx_bytes = rx.split("received,")[0].strip() if "received," in rx else ""
        tx_bytes = rx.split("received,")[1].strip().replace("sent", "").strip() if "received," in rx else ""

        sessions.append({
            "client_id": client_id,
            "public_key": pub_key,
            "tunnel_ip": tunnel_ip,
            "real_ip": real_ip,
            "endpoint": endpoint,
            "handshake": handshake,
            "rx": rx_bytes,
            "tx": tx_bytes,
        })
    return sessions


def is_peer_online(handshake_str):
    """Check if peer had a handshake within last 3 minutes."""
    s = (handshake_str or "").strip()
    # never handshaked ("" / "(none)") or days old -> offline
    if not re.search(r"\d", s) or "day" in s or "week" in s:
        return False
    try:
        parts = s.split(",")
        total_seconds = 0
        for p in parts:
            p = p.strip()
            if "minute" in p:
                total_seconds += int(re.search(r"(\d+)", p).group(1)) * 60
            elif "second" in p:
                total_seconds += int(re.search(r"(\d+)", p).group(1))
            elif "hour" in p:
                total_seconds += int(re.search(r"(\d+)", p).group(1)) * 3600
        return total_seconds < 180
    except Exception:
        return False


def kick_peer(public_key):
    """Remove and re-add peer to force disconnect."""
    try:
        out = subprocess.check_output(["wg", "show", "wg0"], text=True, timeout=5)
        allowed = ""
        found = False
        for line in out.split("\n"):
            if line.strip().startswith("peer:") and public_key in line:
                found = True
            elif found and "allowed ips:" in line:
                allowed = line.split("allowed ips:")[1].strip()
                break

        subprocess.run(["wg", "set", "wg0", "peer", public_key, "remove"], timeout=5)
        if allowed:
            subprocess.run(["wg", "set", "wg0", "peer", public_key, "allowed-ips", allowed], timeout=5)
        return True
    except Exception:
        return False


def check_expiry():
    """Check subscription expiry, lock expired clients."""
    s = load_settings()  # Always reload fresh to avoid overwriting concurrent changes
    subs = s.get("subscriptions", {})
    today = datetime.now().date()
    changed = False

    for client_id, info in list(subs.items()):
        if not info.get("expiry"):
            continue
        try:
            exp_date = datetime.strptime(info["expiry"], "%Y-%m-%d").date()
        except ValueError:
            continue

        days_left = (exp_date - today).days

        if days_left <= 0 and not info.get("locked"):
            info["locked"] = True
            changed = True
            kick_client_by_id(client_id)
            tg_send(f"⛔ <b>{client_id}</b> — подписка истекла! Клиент заблокирован.")
        elif days_left == 3 and not info.get("warn3"):
            info["warn3"] = True
            changed = True
            tg_send(f"⚠️ <b>{client_id}</b> — подписка истекает через 3 дня ({info['expiry']})")
        elif days_left == 1 and not info.get("warn1"):
            info["warn1"] = True
            changed = True
            tg_send(f"⚠️ <b>{client_id}</b> — подписка истекает ЗАВТРА ({info['expiry']})")

    if changed:
        save_settings(s)


def kick_client_by_id(client_id):
    """Find client's public key and kick them."""
    clients = get_clients()
    for c in clients:
        if c.get("client_id") == client_id:
            kick_peer(c.get("public_key", ""))
            return True
    return False


prev_session_keys = None
prev_server_status = {}
_down_streak = {}
_last_fanout = 0
_last_peer_sync = 0
server_stats_cache = {}
server_handshakes_cache = {}


def count_client_peers():
    """Count only client peers (exclude secondary server peers)."""
    clients = get_clients()
    client_pubs = {c.get("public_key", "") for c in clients}
    wg_peers = get_wg_peers()
    return sum(1 for pub in wg_peers if pub in client_pubs)


_net_prev = {}          # key -> (rx, tx, ts) for rate calc
BW_CAP_MBPS = float(os.environ.get("BW_CAP_MBPS", "1000"))  # link cap ref for load fraction

_geo_cache = {}


def _ip_country(ip):
    """Flag + country code for a public IP (ip-api.com, cached). '' for private."""
    ip = (ip or "").strip()
    if not ip or ip.startswith(("10.", "192.168.", "127.")) or ip.startswith("172.16."):
        return ""
    if ip in _geo_cache:
        return _geo_cache[ip]
    res = ""
    try:
        import urllib.request as _u, json as _j
        d = _j.loads(_u.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=4).read())
        cc = (d.get("countryCode") or "").upper()
        if len(cc) == 2 and cc.isalpha():
            flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)
            res = f"{flag} {cc}"
    except Exception:
        res = ""
    _geo_cache[ip] = res
    return res


def _calc_mbps(key, rx, tx, ts):
    """Throughput Mbps from consecutive NIC byte counters. First sample -> 0."""
    prev = _net_prev.get(key)
    _net_prev[key] = (rx, tx, ts)
    if not prev:
        return 0.0
    prx, ptx, pts = prev
    dt = ts - pts
    if dt <= 0 or rx < prx or tx < ptx:   # no time passed / counter reset
        return 0.0
    return round(((rx - prx) + (tx - ptx)) * 8 / (dt * 1e6), 1)


def _local_net_bytes():
    try:
        iface = subprocess.getoutput("ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i==\"dev\") print $(i+1)}' | head -1").strip()
        for line in open("/proc/net/dev"):
            if line.split(":")[0].strip() == iface:
                p = line.split(":")[1].split()
                return int(p[0]), int(p[8])
    except Exception:
        pass
    return 0, 0


def get_local_stats():
    try:
        cpu = subprocess.getoutput("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'").strip()
        mem = subprocess.getoutput("free -m | awk '/Mem:/{printf \"%.0f/%dMB\", $3, $2}'").strip()
        peers = count_client_peers()
        rx, tx = _local_net_bytes()
        mbps = _calc_mbps(SERVER_IP, rx, tx, int(time.time()))
        return {"cpu": cpu + "%", "mem": mem, "peers": peers, "mbps": mbps, "status": "ok"}
    except Exception:
        return {"cpu": "?", "mem": "?", "peers": 0, "mbps": 0.0, "status": "ok"}


def get_remote_stats(server):
    data = None
    for _attempt in range(2):  # retry once: smooths transient timeouts (1-worker agent)
        try:
            data = secondary_api_request(server, "/api/health", timeout=6)
            break
        except Exception:
            data = None
    try:
        if data is None:
            raise Exception("no response")
        # cache handshakes so page renders never block on remote HTTP
        server_handshakes_cache[server.get("ip", "")] = data.get("handshakes", {}) or {}
        # Filter peers: only count known client public keys
        clients = get_clients()
        client_pubs = {c.get("public_key", "") for c in clients}
        remote_keys = data.get("peer_keys", [])
        client_peers = sum(1 for k in remote_keys if k in client_pubs)
        net = data.get("net", {}) or {}
        mbps = _calc_mbps(server.get("ip", ""), net.get("rx", 0), net.get("tx", 0),
                          net.get("ts", int(time.time()))) if net else 0.0
        return {"cpu": data.get("cpu", "—"), "mem": data.get("mem", "—"), "peers": client_peers, "mbps": mbps, "status": "ok" if data.get("status") == "ok" else "down"}
    except Exception:
        return {"cpu": "—", "mem": "—", "peers": 0, "mbps": 0.0, "status": "down"}


def server_load(stats):
    """Estimate server load 0..1 from cached stats (CPU+RAM). Missing stats =
    neutral 0.5; explicitly down = 1.0 (avoid). Used by load-aware rebalance."""
    if not stats:
        return 0.5
    if stats.get("status") == "down":
        return 1.0
    try:
        cpu = float(str(stats.get("cpu", "")).replace("%", "").strip()) / 100.0
    except Exception:
        cpu = 0.5
    mem = 0.5
    try:
        used, total = str(stats.get("mem", "")).replace("MB", "").split("/")
        mem = float(used) / max(float(total), 1.0)
    except Exception:
        pass
    bw = 0.0
    try:
        bw = min(float(stats.get("mbps", 0) or 0) / max(BW_CAP_MBPS, 1.0), 1.0)
    except Exception:
        bw = 0.0
    # bandwidth-aware (v1.3.1-beta): channel load counts alongside CPU/RAM
    return max(0.0, min(1.0, 0.45 * cpu + 0.3 * mem + 0.25 * bw))


def remote_handshakes(server_ip):
    # Pure cache read — the background session_monitor refreshes it every cycle.
    # Page renders must NEVER block on remote HTTP (that caused multi-second hangs).
    return server_handshakes_cache.get(server_ip, {})


def auto_assign_server(client_id):
    s = load_settings()
    assignments = s.get("client_assignments", {})
    if client_id in assignments:
        return assignments[client_id]

    all_servers = get_all_servers_ordered()
    server_ips = [sv["ip"] for sv in all_servers]
    if not server_ips:
        return SERVER_IP

    counts = {ip: 0 for ip in server_ips}
    for cid, sip in assignments.items():
        if sip in counts:
            counts[sip] += 1

    assigned = min(counts, key=counts.get)
    assignments[client_id] = assigned
    s["client_assignments"] = assignments
    save_settings(s)
    return assigned


def add_peer_to_server(server_ip, public_key, allowed_ips):
    """Add WG peer to a server via its API (secondary) or locally (primary)."""
    if server_ip == SERVER_IP:
        # Primary — add locally
        try:
            subprocess.run(["wg", "set", "wg0", "peer", public_key, "allowed-ips", allowed_ips], check=True, timeout=5)
            subprocess.run(["wg-quick", "save", "wg0"], timeout=5)
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}
    # Secondary — call API
    servers = load_servers()
    target_server = {"ip": server_ip, "api_key": ""}
    for srv in servers:
        if srv["ip"] == server_ip:
            target_server = srv
            break
    try:
        return secondary_api_request(target_server, "/api/peers/add", {
            "public_key": public_key, "allowed_ips": allowed_ips
        }, timeout=10)
    except Exception as e:
        return {"status": "error", "msg": str(e)[:200]}


def restart_router_obfuscator(client_id):
    """Restart wg-obfuscator on router via SSH (tries tunnel, then static)."""
    s = load_settings()
    access = s.get("router_access", {}).get(client_id)
    if not access:
        return {"status": "error", "msg": f"No SSH for {client_id}"}
    ok_ip, out = _ssh_run(access, "/opt/etc/init.d/S49wg-obfuscator restart 2>/dev/null; echo OK")
    if ok_ip and "OK" in out:
        return {"status": "ok"}
    return {"status": "error", "msg": out[:200]}


def generate_failover_conf_for_client(client_id):
    s = load_settings()
    assignments = s.get("client_assignments", {})
    assigned_ip = assignments.get(client_id, SERVER_IP)
    all_servers = get_all_servers_ordered()

    by_ip = {sv["ip"]: sv for sv in all_servers}
    ordered = []
    if assigned_ip in by_ip:
        ordered.append(by_ip[assigned_ip])
    for sv in all_servers:
        if sv["ip"] != assigned_ip:
            ordered.append(sv)

    # Get main server WG public key
    try:
        main_wg_pub = subprocess.check_output(["wg", "show", "wg0", "public-key"], text=True, timeout=5).strip()
    except Exception:
        main_wg_pub = ""

    lines = ["# Phobos Failover Configuration"]
    for i, srv in enumerate(ordered, 1):
        lines.append(f"SERVER_{i}={client_endpoint(srv['ip'])}:{srv.get('ports', '2083,5443,993')}")
        lines.append(f"KEY_{i}={srv.get('obfuscator_key', '')}")
        wg_pub = main_wg_pub if srv.get("is_primary") else srv.get("wg_public_key", "")
        if wg_pub:
            lines.append(f"WGKEY_{i}={wg_pub}")
    # Obfuscator params (delivered live; router applies to wg-obfuscator.conf)
    obf = s.get("obf_params", {})
    masking = (obf.get("masking") or "AUTO").upper()
    if masking not in ("AUTO", "STUN", "NONE"):
        masking = "AUTO"
    lines.append(f"OBF_MASKING={masking}")
    lines.append(f"OBF_MAX_DUMMY={obf.get('max_dummy', '4')}")
    lines.append(f"OBF_IDLE={obf.get('idle', '300')}")
    return "\n".join(lines) + "\n"


def panel_version():
    try:
        return open(os.path.join(PANEL_DIR, ".version")).read().strip()
    except Exception:
        return "unknown"


GH_TOKEN_FILE = "/opt/phobos-panel/.gh_token"


def gh_token_present():
    try:
        return os.path.exists(GH_TOKEN_FILE) and os.path.getsize(GH_TOKEN_FILE) > 0
    except Exception:
        return False


def save_gh_token(tok):
    tok = (tok or "").strip()
    if not tok:
        return False
    fd = os.open(GH_TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, tok.encode())
    finally:
        os.close(fd)
    return True


BACKUP_SCRIPT = "/opt/Phobos/server/phobos-backup.sh"
UPDATE_SCRIPT = f"{PHOBOS_DIR}/server/update.sh"
UPDATE_BIN = "/usr/local/bin/phobos-update"


def _update_repo_for_ref(ref):
    ref = (ref or "").strip()
    if ref in ("beta", "dev"):
        return "andrey271192/PCA_Phobos-dev", ref
    if ref in ("stable", "main", "") or ref.startswith("v"):
        return "andrey271192/PCA_Phobos", "main" if ref in ("stable", "") else ref
    version = panel_version()
    if "beta" in version:
        return "andrey271192/PCA_Phobos-dev", "beta"
    if "dev" in version:
        return "andrey271192/PCA_Phobos-dev", "dev"
    return "andrey271192/PCA_Phobos", "main"


def _current_update_ref(arg):
    arg = (arg or "").strip()
    if arg and not arg.startswith("-"):
        return arg
    version = panel_version()
    if "beta" in version:
        return "beta"
    if "dev" in version:
        return "dev"
    return "main"


def _find_update_runner():
    for path in (UPDATE_SCRIPT, UPDATE_BIN):
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return ""


def _restore_update_script(ref):
    _repo, branch = _update_repo_for_ref(ref)
    kind = "tag" if branch.startswith("v") else "branch"
    r = None
    for url in (f"{PCA_GIT}/raw/{kind}/{branch}/update.sh", f"{PCA_GH_RAW}/{branch}/update.sh"):
        r = subprocess.run(["curl", "-fsSL", "-m", "25", f"{url}?cb={int(time.time())}"],
                           capture_output=True, text=True, timeout=35)
        if r.returncode == 0 and (r.stdout or "").startswith("#!"):
            break
    if r is None or r.returncode != 0 or not (r.stdout or "").startswith("#!"):
        return False, f"update helper restore failed for {branch}: {(r.stderr if r else '') or 'download failed'}"
    repo = PCA_GIT
    os.makedirs(os.path.dirname(UPDATE_SCRIPT), exist_ok=True)
    tmp = UPDATE_SCRIPT + ".tmp"
    Path(tmp).write_text(r.stdout)
    os.chmod(tmp, 0o755)
    os.replace(tmp, UPDATE_SCRIPT)
    try:
        if os.path.islink(UPDATE_BIN) or os.path.exists(UPDATE_BIN):
            os.remove(UPDATE_BIN)
        os.symlink(UPDATE_SCRIPT, UPDATE_BIN)
    except Exception:
        pass
    return True, f"update helper restored from {repo}/{branch}"


def run_update(arg):
    runner = _find_update_runner()
    prefix = ""
    if not runner:
        ok, note = _restore_update_script(_current_update_ref(arg))
        prefix = note + "\n"
        if ok:
            runner = _find_update_runner()
    if not runner:
        return prefix + f"update error: helper not found ({UPDATE_SCRIPT})"
    try:
        env = {**os.environ}
        try:
            tok = Path(GH_TOKEN_FILE).read_text().strip()
            if tok:
                env["GH_TOKEN"] = tok
        except Exception:
            pass
        r = subprocess.run([runner, arg],
                           capture_output=True, text=True, timeout=180, env=env)
        return (prefix + r.stdout + r.stderr)[-1800:]
    except Exception as e:
        return prefix + "update error: " + str(e)


def warp_status():
    try:
        r = subprocess.run(
            ["/opt/Phobos/server/phobos-warp.sh", "status"],
            capture_output=True, text=True, timeout=20
        )
        raw = (r.stdout or "").strip() or (r.stderr or "").strip()
        data = json.loads(raw) if raw.startswith("{") else {}
        if not data:
            data = {"enabled": False, "configured": False, "service": "unknown", "error": raw[-300:]}
        return data
    except Exception as e:
        return {"enabled": False, "configured": False, "service": "missing", "error": str(e)}


# ── extras: domain / client endpoint (cascade) / guard ───────────────────────
def run_server_script(name, *args, timeout=240, env=None):
    path = f"{PHOBOS_DIR}/server/{name}"
    if not os.path.exists(path):
        return False, f"{name} not found — phobos-update"
    try:
        r = subprocess.run([path, *[str(a) for a in args]], capture_output=True, text=True,
                           timeout=timeout, env={**os.environ, **(env or {})})
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or ""))[-2000:]
    except Exception as e:
        return False, f"{name}: {e}"


def script_status(name):
    ok, out = run_server_script(name, "status", timeout=20)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return {}


def client_endpoint(ip):
    """Host clients dial for server `ip`: a domain or a cascade entry, else the IP.
    A host that is not a secondary's IP (old endpoint, domain) means the primary."""
    eps = load_settings().get("endpoints", {})
    if ip != SERVER_IP and ip not in {sv.get("ip") for sv in load_servers()}:
        ip = SERVER_IP
    return (eps.get(ip) or "").strip() or ip


_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


def save_client_endpoints(form):
    s = load_settings()
    eps = {}
    for srv in get_all_servers_ordered():
        ip = srv["ip"]
        v = (form.get("ep_" + ip, "") or "").strip()
        if v and not _HOST_RE.match(v):
            return False, tr("Неверный адрес: ", "Bad host: ") + v
        if v and v != ip:
            eps[ip] = v
    s["endpoints"] = eps
    save_settings(s)
    # new client packages read CLIENT_ENDPOINT from server.env
    try:
        lines = [ln for ln in open(SERVER_ENV).read().splitlines() if not ln.startswith("CLIENT_ENDPOINT=")]
        if eps.get(SERVER_IP):
            lines.append("CLIENT_ENDPOINT=" + eps[SERVER_IP])
        Path(SERVER_ENV).write_text("\n".join(lines) + "\n")
    except Exception as e:
        return False, f"server.env: {e}"
    # routers pick the new address up through pull (failover.conf) in ~15s
    for c in get_clients():
        try:
            fanout_router_config(c.get("client_id", ""))
        except Exception:
            pass
    return True, tr("Адреса сохранены. Роутеры получат их через pull, телефонам — заново открыть ссылку/QR.",
                    "Endpoints saved. Routers get them via pull; phones must reopen the link/QR.")


def run_speedtest(ip):
    """Real internet speed of a server (bytes really moved), cached in settings."""
    try:
        if not ip or ip == SERVER_IP:
            ok, out = run_server_script("phobos-speedtest.sh", timeout=90)
            res = json.loads(out.strip().splitlines()[-1])
        else:
            srv = next((x for x in load_servers() if x.get("ip") == ip), None)
            if not srv:
                return {"error": "unknown server"}
            res = secondary_api_request(srv, "/api/speedtest", {}, timeout=90)
        if "download_mbit" not in res:
            return {"error": res.get("error") or res.get("msg") or "no data"}
    except Exception as e:
        return {"error": str(e)}
    s = load_settings()
    s.setdefault("speedtests", {})[ip or SERVER_IP] = res
    save_settings(s)
    return res


LIMITS_FILE = f"{PHOBOS_DIR}/server/limits.conf"


def speed_limits_text():
    lim = load_settings().get("speed_limits", {})
    out = []
    for c in get_clients():
        mbit = lim.get(c.get("client_id", ""))
        tip = (c.get("tunnel_ip_v4") or "").split("/")[0].strip()
        if mbit and tip:
            out.append(f"{tip} {int(mbit)}")
    return "\n".join(out) + ("\n" if out else "")


def apply_speed_limits(push=True):
    """Write limits.conf, rebuild tc on wg0 here and on every secondary."""
    text = speed_limits_text()
    try:
        Path(LIMITS_FILE).write_text(text)
    except Exception as e:
        return False, f"limits.conf: {e}"
    ok, out = run_server_script("phobos-limit.sh", "apply", timeout=30)
    if push:
        for srv in load_servers():
            if srv.get("enabled", True) and server_stats_cache.get(srv.get("ip"), {}).get("status") != "down":
                try:
                    secondary_api_request(srv, "/api/limits", {"limits": text}, timeout=5)
                except Exception:
                    pass
    return ok, out.strip() or "ok"


def limits_need_reapply():
    """wg0 restart wipes tc — notice it and rebuild."""
    try:
        if not os.path.getsize(LIMITS_FILE):
            return False
        r = subprocess.run(["tc", "qdisc", "show", "dev", "wg0"], capture_output=True, text=True, timeout=5)
        return "htb" not in r.stdout
    except Exception:
        return False


client_rates = {}   # pub -> (down_mbit, up_mbit) as seen from the client


def rate_sampler():
    """Real per-client speed from WireGuard byte counters, every 5 s."""
    prev, prev_t = {}, 0.0
    while True:
        try:
            out = subprocess.run(["wg", "show", "wg0", "transfer"], capture_output=True, text=True, timeout=5).stdout
            now = time.time()
            cur = {}
            for ln in out.splitlines():
                p = ln.split()
                if len(p) == 3:
                    cur[p[0]] = (int(p[1]), int(p[2]))
            if prev_t:
                dt = now - prev_t
                rates = {}
                for pub, (rx, tx) in cur.items():
                    if pub in prev:
                        # server rx = client upload, server tx = client download
                        up = max(0, rx - prev[pub][0]) * 8 / dt / 1e6
                        down = max(0, tx - prev[pub][1]) * 8 / dt / 1e6
                        if up > 0.01 or down > 0.01:
                            rates[pub] = (down, up)
                client_rates.clear()
                client_rates.update(rates)
            prev, prev_t = cur, now
        except Exception:
            pass
        time.sleep(5)


def _swap_host(hostport, ip_to_host):
    host, sep, port = hostport.rpartition(":")
    return (ip_to_host(host) + sep + port) if sep else hostport


def run_warp(action, *extra):
    try:
        r = subprocess.run(
            ["/opt/Phobos/server/phobos-warp.sh", action, *[str(x) for x in extra if x is not None]],
            capture_output=True, text=True, timeout=180
        )
        return ((r.stdout or "") + (r.stderr or ""))[-1600:]
    except Exception as e:
        return "warp error: " + str(e)


def warp_toggle_client(cid, enable=True):
    client = next((c for c in get_clients(include_orphans=True) if c.get("client_id") == cid), None)
    if not client:
        return False, tr("Клиент не найден.", "Client not found.")
    tip = (client.get("tunnel_ip_v4") or "").split("/")[0].strip()
    if not tip:
        return False, tr("У клиента нет tunnel IP.", "Client has no tunnel IP.")
    s = load_settings()
    current = set(str(x).strip() for x in s.get("warp_clients", []) if str(x).strip())
    if enable:
        current.add(cid)
    else:
        current.discard(cid)
    s["warp_clients"] = sorted(current)
    save_settings(s)
    st = warp_status()
    if st.get("mode") == "egress" and st.get("service") == "active":
        out = run_warp("client-enable" if enable else "client-disable", tip)
        if "error" in out.lower() or "required" in out.lower():
            return False, out
        return True, out
    return True, tr("Сохранено. Применится после включения WARP egress.", "Saved. Applies after WARP egress is enabled.")


def apply_warp_form(s):
    cfg = get_warp_settings(s)
    cfg["mode"] = request.form.get("warp_mode", cfg["mode"]).strip() or "egress"
    if cfg["mode"] not in ("egress", "relay"):
        cfg["mode"] = "egress"
    cfg["profile_source"] = request.form.get("warp_profile_source", cfg["profile_source"]).strip() or "free"
    if cfg["profile_source"] not in ("free", "custom"):
        cfg["profile_source"] = "free"
    cfg["relay_ports"] = request.form.get("warp_relay_ports", cfg["relay_ports"]).strip() or "4500"
    cfg["relay_target"] = request.form.get("warp_relay_target", cfg["relay_target"]).strip()
    cfg["license_key"] = request.form.get("warp_license_key", cfg.get("license_key", "")).strip()
    s["warp"] = cfg
    profile_text = request.form.get("warp_custom_profile", "")
    if request.form.get("warp_clear_license") == "1":
        cfg["license_key"] = ""
        delete_warp_license_key()
    elif cfg["license_key"]:
        save_warp_license_key(cfg["license_key"])
    if request.form.get("warp_clear_custom") == "1":
        delete_custom_warp_profile()
    elif profile_text.strip():
        save_custom_warp_profile(profile_text)
    return cfg


def build_phone_config(cid, mode="android"):
    """Assemble a phone client config from the client's files.
    android = WireGuard + [instance] obfuscator -> phobos:// link (PhobosWG app).
    ios     = plain WireGuard (no obfuscation), Endpoint -> server:51820."""
    import base64, urllib.parse
    cdir = os.path.join(CLIENTS_DIR, cid)
    wgpath = os.path.join(cdir, cid + ".conf")
    instpath = os.path.join(cdir, "wg-obfuscator.conf")
    if not os.path.exists(wgpath):
        return None, None
    wg = open(wgpath).read().rstrip()
    if mode == "ios":
        server_ip = SERVER_IP
        try:
            for ln in open(instpath):
                if ln.strip().startswith("target"):
                    server_ip = ln.split("=", 1)[1].strip().split(":")[0]
                    break
        except Exception:
            pass
        try:
            server_ip = client_endpoint(server_ip)
        except Exception:
            pass
        out = []
        for ln in wg.split("\n"):
            if ln.strip().startswith("Endpoint"):
                out.append("Endpoint = %s:51820" % server_ip)
            else:
                out.append(_normalize_wg_key_line(ln))
        return "\n".join(out) + "\n", None
    inst = ""
    if os.path.exists(instpath):
        inst = open(instpath).read().strip()
        inst = "\n".join(
            ("target = " + _swap_host(ln.split("=", 1)[1].strip(), client_endpoint))
            if ln.strip().startswith("target") and "=" in ln else ln
            for ln in inst.split("\n"))
    conf = wg + "\n\n" + inst + "\n"
    payload = _prepare_phoboswg_payload(conf)
    b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    link = "phobos://" + b64 + "#" + urllib.parse.quote(cid or "none")
    return payload, link


def _prepare_phoboswg_payload(conf):
    """Normalize Android PhobosWG phobos:// payload. Do not use for raw .conf."""
    mandatory = {
        "[interface]": ["PrivateKey", "Address", "MTU", "DNS"],
        "[peer]": ["PublicKey", "AllowedIPs", "PersistentKeepalive", "Endpoint"],
        "[instance]": ["source-if", "source-lport", "target", "key", "masking",
                       "verbose", "idle-timeout", "max-dummy"],
    }
    sections = []
    cur = None
    for ln in conf.split("\n"):
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = [s, []]
            sections.append(cur)
        elif cur is not None:
            cur[1].append(ln)
    out = []
    for header, lines in sections:
        normalized = []
        for ln in lines:
            if "=" not in ln:
                normalized.append(ln)
                continue
            key, value = ln.split("=", 1)
            k = key.strip().lower()
            v = value.strip()
            if k in ("privatekey", "publickey", "presharedkey"):
                ln = "%s = %s" % (key.strip(), _normalize_wg_key_value(v))
                v = _normalize_wg_key_value(v)
            if k == "presharedkey" and v.lower() in ("", "none"):
                continue
            if header.lower() == "[peer]" and k == "allowedips":
                parts = [p.strip() for p in v.split(",") if p.strip()]
                if "0.0.0.0/0" not in parts:
                    parts.insert(0, "0.0.0.0/0")
                if "::/0" not in parts:
                    parts.append("::/0")
                ln = "%s = %s" % (key.strip(), ", ".join(parts))
            elif header.lower() == "[instance]" and k == "masking" and v.upper() == "AUTO":
                ln = "%s = STUN" % key.strip()
            normalized.append(ln)
        lines = normalized
        keys = {ln.split("=", 1)[0].strip().lower() for ln in lines if "=" in ln}
        while lines and lines[-1].strip() == "":
            lines.pop()
        for req in mandatory.get(header.lower(), []):
            if req.lower() not in keys:
                lines.append("%s = none" % req)
        out.append(header)
        out.extend(lines)
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def _normalize_wg_key_line(line):
    if "=" not in line:
        return line
    key, value = line.split("=", 1)
    if key.strip().lower() not in ("privatekey", "publickey", "presharedkey"):
        return line
    return "%s = %s" % (key.strip(), _normalize_wg_key_value(value.strip()))


def _normalize_wg_key_value(value):
    """Restore dropped base64 padding for WireGuard 32-byte keys."""
    value = (value or "").strip()
    if not value or value.lower() == "none":
        return value
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if any(ch not in alphabet for ch in value):
        return value
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    if len(padded) == 44:
        return padded
    return value


def _pad_conf_with_none(conf):
    """Insert '<key> = none' for every missing mandatory PhobosWG field
    (phobos:// spec 2.3). Only for phobos:// payload, NOT raw .conf."""
    mandatory = {
        "[interface]": ["PrivateKey", "Address", "MTU", "DNS"],
        "[peer]": ["PublicKey", "PresharedKey", "AllowedIPs", "PersistentKeepalive", "Endpoint"],
        "[instance]": ["source-if", "source-lport", "target", "key", "masking",
                       "verbose", "idle-timeout", "max-dummy"],
    }
    sections = []
    cur = None
    for ln in conf.split("\n"):
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = [s, []]
            sections.append(cur)
        elif cur is not None:
            cur[1].append(ln)
    out = []
    for header, lines in sections:
        keys = {ln.split("=", 1)[0].strip().lower() for ln in lines if "=" in ln}
        while lines and lines[-1].strip() == "":
            lines.pop()
        for req in mandatory.get(header.lower(), []):
            if req.lower() not in keys:
                lines.append("%s = none" % req)
        out.append(header)
        out.extend(lines)
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def qr_datauri(data):
    try:
        import qrcode, io, base64
        # ECC L = fewer modules for the same data (phobos:// links are long).
        # box_size/border chosen so native PNG ~matches the 300px display ->
        # no CSS downscale blur, scannable by phone cameras.
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,
                           box_size=4, border=3)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""


def fanout_router_config(client_id):
    """Push this client's failover.conf to every secondary server's agent so
    routers can PULL it through the tunnel server IP (:8444) — survives a public
    panel-IP ban and follows the active server. Best-effort, non-blocking."""
    try:
        conf = generate_failover_conf_for_client(client_id)
    except Exception:
        return
    for srv in load_servers():
        ip = srv.get("ip", "")
        if not ip:
            continue
        # skip servers the monitor already knows are down (avoid blocking)
        if server_stats_cache.get(ip, {}).get("status") == "down":
            continue
        try:
            secondary_api_request(srv, "/api/router-config-set",
                                  {"client_id": client_id, "conf": conf}, timeout=3)
        except Exception:
            pass


def _ssh_run(access, cmd, timeout=20):
    """Try SSH: tunnel IP first, then static IP as fallback."""
    ssh_user = access.get("ssh_user", "root")
    ssh_pass = access.get("ssh_pass", "")
    ssh_port = str(access.get("ssh_port", "22") or "22")
    ips_to_try = []
    if access.get("ssh_ip"):
        ips_to_try.append(access["ssh_ip"])
    if access.get("ssh_static"):
        ips_to_try.append(access["ssh_static"])
    if not ips_to_try or not ssh_pass:
        return None, "SSH IP/pass missing"
    for ip in ips_to_try:
        try:
            result = subprocess.run(
                ["sshpass", "-p", ssh_pass, "ssh",
                 "-p", ssh_port, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                 f"{ssh_user}@{ip}", cmd],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return ip, result.stdout
        except Exception:
            continue
    return None, f"SSH failed on all IPs: {', '.join(ips_to_try)}"


def push_config_to_router(client_id):
    s = load_settings()
    access = s.get("router_access", {}).get(client_id)
    if not access:
        return {"status": "error", "msg": f"No SSH for {client_id}"}

    conf = generate_failover_conf_for_client(client_id)
    write_cmd = f"mkdir -p /opt/etc/Phobos && cat > /opt/etc/Phobos/failover.conf << 'FAILCONF'\n{conf}FAILCONF"

    ok_ip, out = _ssh_run(access, write_cmd)
    if ok_ip:
        return {"status": "ok", "msg": f"Config pushed to {client_id} ({ok_ip})"}
    return {"status": "error", "msg": out[:200]}


def session_monitor():
    global prev_session_keys, prev_server_status, server_stats_cache, _last_fanout, _last_peer_sync, _down_streak
    while True:
        try:
            s = load_settings()
            interval = s.get("monitor_interval", 30)

            # Client session monitoring
            sessions = get_active_sessions()
            current_keys = set()
            for sess in sessions:
                if is_peer_online(sess.get("handshake", "")):
                    key = (sess["client_id"], sess["real_ip"])
                    current_keys.add(key)

            if prev_session_keys is not None:
                labels = s.get("labels", {})
                for key in current_keys - prev_session_keys:
                    client_id, real_ip = key
                    label = labels.get(real_ip, "")
                    name = f"{label} ({real_ip})" if label else real_ip
                    if notify_on(client_id):
                        tg_send(f"🟢 <b>{client_id}</b> connected — {name}")

                for key in prev_session_keys - current_keys:
                    client_id, real_ip = key
                    label = labels.get(real_ip, "")
                    name = f"{label} ({real_ip})" if label else real_ip
                    if notify_on(client_id):
                        tg_send(f"🔴 <b>{client_id}</b> disconnected — {name}")

            prev_session_keys = current_keys

            # Server health monitoring
            servers = load_servers()
            local_stats = get_local_stats()
            server_stats_cache[SERVER_IP] = local_stats

            DOWN_CONFIRM = 3  # consecutive failed cycles before declaring a server DOWN
            for srv in servers:
                ip = srv["ip"]
                stats = get_remote_stats(srv)
                raw = stats.get("status", "down")
                streak = _down_streak.get(ip, 0)
                streak = streak + 1 if raw == "down" else 0
                _down_streak[ip] = streak
                # update cache on OK, or only once a DOWN is confirmed (keep last-good on transient)
                if raw == "ok" or streak >= DOWN_CONFIRM:
                    server_stats_cache[ip] = stats
                eff = "down" if streak >= DOWN_CONFIRM else "ok"
                was_up = prev_server_status.get(ip, "ok")
                if was_up == "ok" and eff == "down":
                    tg_send(f"🔴 <b>Server {ip}</b> DOWN!")
                elif was_up == "down" and eff == "ok":
                    tg_send(f"🟢 <b>Server {ip}</b> back ONLINE")
                prev_server_status[ip] = eff

            # periodic config fan-out to secondaries (covers CLI-created clients
            # and config drift; gated ~5 min, skips down servers)
            global _last_fanout
            if time.time() - _last_fanout >= 300:
                _last_fanout = time.time()
                for _c in get_clients():
                    fanout_router_config(_c.get("client_id", ""))

            # periodic peer repair to secondaries. This is what makes router
            # server-failover work without pressing "Sync" after old clients
            # or newly added secondary servers.
            if time.time() - _last_peer_sync >= 300:
                _last_peer_sync = time.time()
                sync_missing_peers_to_secondaries()
                if load_settings().get("speed_limits"):
                    apply_speed_limits()
            elif limits_need_reapply():
                apply_speed_limits(push=False)

            check_expiry()
            time.sleep(interval)
        except Exception:
            time.sleep(30)


monitor_thread = threading.Thread(target=session_monitor, daemon=True)
monitor_thread.start()
bot_thread = threading.Thread(target=telegram_bot, daemon=True)
bot_thread.start()


def finish_legacy_update():
    """1.2.x/1.3.x updaters only know their own file list. After such an update
    the new update.sh is already in place, so run it once more (detached from
    the panel cgroup) to fetch the scripts the old list missed."""
    need = [f"{PHOBOS_DIR}/server/{n}" for n in
            ("phobos-guard.sh", "phobos-cascade.sh", "phobos-domain.sh", "phobos-limit.sh",
             "phobos-speedtest.sh", "phobos-warp.sh", "phobos-backup.sh")]
    marker = os.path.join(PANEL_DIR, ".finish-update")
    runner = f"{PHOBOS_DIR}/server/update.sh"
    try:
        recent = time.time() - os.path.getmtime(marker) < 6 * 3600
    except OSError:
        recent = False
    if all(os.path.exists(p) for p in need) or recent or not os.path.exists(runner):
        return
    try:
        Path(marker).write_text(str(int(time.time())))
        ref = "main"
        try:
            ch = open(os.path.join(PANEL_DIR, ".channel")).read().strip()
            ref = ch if ch in ("beta", "dev") or ch.endswith(("-dev", "-beta")) else "main"
        except Exception:
            pass
        subprocess.Popen(["systemd-run", "--unit=phobos-finish-update", "--collect", runner, ref],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


finish_legacy_update()
threading.Thread(target=rate_sampler, daemon=True).start()


PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phobos VPN Panel</title>
<script>(function(){var t;try{t=localStorage.getItem('theme')}catch(e){}if(!t)t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=t})();
function toggleTheme(){var t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('theme',t)}catch(e){}}</script>
<style>
:root{--bg:#f1f5f9;--card:#ffffff;--border:#dbe2ea;--text:#0f172a;--muted:#64748b;--accent:#4338ca;--hover:#f8fafc;--navact:#e0e7ff;--err:#b91c1c;--warn:#b45309;color-scheme:light}
:root[data-theme="dark"]{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#a5b4fc;--hover:#262f3d;--navact:#312e81;--err:#fca5a5;--warn:#fcd34d;color-scheme:dark}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#1e1b4b,#312e81);padding:20px;text-align:center;border-bottom:2px solid #4f46e5}
.header h1{font-size:1.6em;color:#c7d2fe}
.header .subtitle{font-size:.85em;color:#a5b4fc;margin-top:4px}
.container{max-width:min(1580px,calc(100vw - 56px));margin:20px auto;padding:0 16px}
.card{background:var(--card);border-radius:12px;padding:20px;margin-bottom:16px;border:1px solid var(--border);overflow:hidden}
.card h2{color:var(--accent);font-size:1.1em;margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:8px}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--muted);font-size:.8em;padding:8px 6px;border-bottom:1px solid var(--border)}
td{padding:8px 6px;border-bottom:1px solid var(--border);font-size:.9em}
tr:hover{background:var(--hover)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600}
.badge-on{background:#065f46;color:#6ee7b7}
.badge-off{background:#7f1d1d;color:#fca5a5}
.badge-warn{background:#78350f;color:#fcd34d}
.badge-lock{background:#581c87;color:#d8b4fe}
.btn{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:.85em;color:#fff;text-decoration:none;display:inline-block}
.btn-primary{background:#4f46e5}.btn-primary:hover{background:#4338ca}
.btn-danger{background:#dc2626}.btn-danger:hover{background:#b91c1c}
.btn-sm{padding:4px 10px;font-size:.78em}
input,select,textarea{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:.9em}
input:focus,select:focus,textarea:focus{outline:none;border-color:#4f46e5;box-shadow:0 0 0 2px rgba(79,70,229,.18)}
textarea::placeholder{color:var(--muted)}
.form-row{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}
.form-row label{min-width:120px;color:var(--muted);font-size:.85em}
.expiry-badge{font-size:.78em;padding:2px 6px;border-radius:6px}
.nav{display:flex;gap:10px;justify-content:center;margin:16px 0}
.nav a{color:var(--accent);text-decoration:none;padding:6px 16px;border-radius:6px;font-size:.9em}
.nav a:hover,.nav a.active{background:var(--navact);color:var(--accent)}
.footer{text-align:center;padding:30px 20px;color:var(--muted);font-size:.8em;border-top:1px solid var(--border);margin-top:30px}
.footer a{color:#6366f1;text-decoration:none}
.footer a:hover{text-decoration:underline}
.login-box{max-width:360px;margin:80px auto;padding:30px;background:var(--card);border-radius:12px;border:1px solid var(--border)}
.login-box h2{text-align:center;color:var(--accent);margin-bottom:20px}
.login-box input{width:100%;margin-bottom:12px}
.login-box .btn{width:100%}
.alert{padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:.85em}
.alert-error{background:#7f1d1d;color:#fca5a5;border:1px solid #991b1b}
.alert-ok{background:#065f46;color:#6ee7b7;border:1px solid #047857}
.help{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;background:var(--navact);color:var(--accent);font-size:11px;font-weight:700;cursor:pointer;margin-left:4px;user-select:none;flex:none}
.help:hover{background:#4f46e5;color:#fff}
.help-box{display:none;background:var(--bg);border:1px solid #4f46e5;color:var(--text);padding:8px 11px;border-radius:8px;font-size:.78em;max-width:340px;margin-left:6px;line-height:1.4;vertical-align:middle}
.help-box.show{display:inline-block}
.table-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:2px}
.wide-table{min-width:900px}
.client-table{min-width:1220px}
.client-table th,.client-table td{vertical-align:middle}
.client-name-form,.client-server-form,.client-expiry-form{display:flex;gap:6px;align-items:center;flex-wrap:nowrap}
.client-name-form input{width:150px}
.client-server-form select{width:230px}
.client-expiry-form input[type=date]{width:145px}
.client-actions-cell{min-width:240px}
.client-actions{display:grid;grid-template-columns:repeat(3,max-content);gap:6px;align-items:center}
.client-actions form{margin:0}
.client-actions .btn{white-space:nowrap}
.ccard{border:1px solid var(--border);border-radius:10px;padding:10px 12px;margin-bottom:8px;background:var(--hover)}
.ctop{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center}
.cname{font-weight:600}.cip{color:var(--muted);font-size:.85em;font-family:Menlo,monospace}
.cspeed{font-size:.8em;color:var(--accent);font-family:Menlo,monospace}
.cctl,.cact{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;margin-top:8px}
.cctl form,.cact form{display:flex;gap:4px;align-items:center;margin:0}
.cctl select,.cctl input{padding:4px 6px;font-size:.82em}
.cctl select{max-width:220px}.cunit{font-size:.78em;color:var(--muted)}
.cact .btn{padding:4px 9px}
.router-access-table{min-width:1420px}
.router-access-table th,.router-access-table td{white-space:nowrap;vertical-align:middle}
.router-access-table input{width:100%}
@media (max-width: 760px){
  .container{max-width:100%;padding:0 10px}
  .header{padding:12px}.header h1{font-size:1.25em}
  .nav{gap:4px}.nav a{padding:5px 9px;white-space:nowrap;font-size:.85em}
  .cctl select{max-width:100%}
  .form-row label{min-width:0;width:100%}
  .card{padding:14px}
  .nav{flex-wrap:wrap;justify-content:center;padding-bottom:4px}
}
</style>
</head>
<body>
<div class="header">
<h1>🛡️ Phobos VPN Panel</h1>
<div class="subtitle">Obfuscated WireGuard · """ + SERVER_IP + """</div>
</div>
CONTENT
<div class="footer">
<b style="color:var(--accent)">PCA Phobos Panel</b> — панель управления &copy; <a href="https://git.bobyrev.com/PCA/PCA_Phobos" target="_blank" rel="noopener">andrey271192</a><br>
Поддержать проект: <a href="https://boosty.to/andrey27/donate" target="_blank" rel="noopener">💖 Boosty</a> · <a href="https://finance.ozon.ru/apps/sbp/ozonbankpay/019dc200-2a5d-7931-a619-782d285f6798" target="_blank" rel="noopener">💳 Ozon Bank</a> · <a href="https://t.me/PCAdministration" target="_blank" rel="noopener">✉️ Telegram</a>
<div style="margin-top:8px;font-size:.88em;color:var(--muted);line-height:1.7;text-align:left;max-width:660px;margin:8px auto 0">
<b>Создано на основе открытых проектов:</b><br>
&bull; <a href="https://github.com/Ground-Zerro/Phobos" target="_blank" rel="noopener">Phobos</a> — обфусцированный WireGuard VPN, автор <b>Ground_Zerro</b> &middot; <a href="https://boosty.to/ground_zerro" target="_blank" rel="noopener">поддержать</a><br>
&bull; <a href="https://github.com/wg-easy/wg-easy" target="_blank" rel="noopener">WireGuard Easy</a> — веб-панель WireGuard (AGPL-3.0), автор <b>Emile Nijssen</b> &middot; <a href="https://github.com/sponsors/WeeJeWel" target="_blank" rel="noopener">поддержать</a><br>
&bull; <a href="https://github.com/ClusterM/wg-obfuscator" target="_blank" rel="noopener">wg-obfuscator</a> — обфускация WireGuard-трафика (GPL-3.0), автор <b>ClusterM</b> &middot; <a href="https://boosty.to/cluster" target="_blank" rel="noopener">поддержать</a>
</div>
</div>
<script>
function showHelp(el){var b=el.nextElementSibling; if(b&&b.classList.contains('help-box')){b.classList.toggle('show');}}
</script>
</body></html>"""


def render(content):
    return PAGE.replace("CONTENT", content)


@app.errorhandler(404)
def not_found(_e):
    return render(f'''
    <div class="container">
    <div class="card">
    <h2>{tr("Страница не найдена","Page not found")}</h2>
    <p style="color:var(--muted)">{tr("Возможно, ссылка устарела или раздел был переименован.","Link may be outdated or section was renamed.")}</p>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <a href="/sessions" class="btn btn-primary btn-sm">{tr("Сессии","Sessions")}</a>
      <a href="/clients" class="btn btn-primary btn-sm">{tr("Клиенты","Clients")}</a>
      <a href="/labels" class="btn btn-primary btn-sm">{tr("Метки","Labels")}</a>
      <a href="/settings" class="btn btn-primary btn-sm">{tr("Настройки","Settings")}</a>
    </div>
    </div>
    </div>
    '''), 404


@app.errorhandler(500)
def server_error(_e):
    return render(f'''
    <div class="container">
    <div class="card">
    <h2>{tr("Внутренняя ошибка панели","Panel internal error")}</h2>
    <p style="color:var(--err)">{tr("Панель поймала ошибку. Обнови страницу. Если повторяется — проверь логи сервиса phobos-panel/phobos-dev-test.","Panel hit an error. Refresh page. If it repeats, check phobos-panel/phobos-dev-test logs.")}</p>
    <a href="/sessions" class="btn btn-primary btn-sm">{tr("На главную","Back to dashboard")}</a>
    </div>
    </div>
    '''), 500


@app.errorhandler(413)
def payload_too_large(_e):
    return render(f'''
    <div class="container">
    <div class="card">
    <h2>{tr("Файл слишком большой","File too large")}</h2>
    <p style="color:var(--err)">{tr("Лимит загрузки 64 MB. Уменьши файл или восстанавливай через shell.","Upload limit is 64 MB. Shrink file or restore via shell.")}</p>
    <a href="/settings" class="btn btn-primary btn-sm">{tr("К настройкам","Back to settings")}</a>
    </div>
    </div>
    '''), 413


def cur_lang():
    try:
        from flask import request as _rq
        return "en" if _rq.cookies.get("lang", "ru") == "en" else "ru"
    except Exception:
        return "ru"


def tr(ru, en):
    return ru if cur_lang() == "ru" else en


def hlp(ru, en):
    """Inline '?' badge; click reveals a plain-language explanation (bilingual)."""
    txt = (ru if cur_lang() == "ru" else en).replace('"', '&quot;')
    return ('<span class="help" onclick="showHelp(this)">?</span>'
            '<span class="help-box">' + txt + '</span>')


def nav(active, sess_count=None):
    L = cur_lang()
    items = [
        ("sessions", "/sessions", "Сессии", "Sessions"),
        ("clients",  "/clients",  "Клиенты", "Clients"),
        ("labels",   "/labels",   "Метки",  "Labels"),
        ("servers",  "/servers",  "Серверы", "Servers"),
        ("settings", "/settings", "Настройки", "Settings"),
        ("logout",   "/logout",   "Выход",  "Logout"),
    ]
    parts = ['<div class="nav">']
    for key, href, ru, en in items:
        lbl = ru if L == "ru" else en
        if key == "sessions" and sess_count is not None:
            lbl = lbl + " (" + str(sess_count) + ")"
        cls = ' class="active"' if key == active else ''
        parts.append('<a href="' + href + '"' + cls + '>' + lbl + '</a>')
    other = "en" if L == "ru" else "ru"
    flag = "EN" if L == "ru" else "RU"
    parts.append('<a href="/lang/' + other + '" title="language" style="margin-left:12px;border:1px solid #4f46e5;color:var(--accent)">' + flag + '</a>')
    parts.append('<a href="#" onclick="toggleTheme();return false" title="theme" style="border:1px solid #4f46e5">◐</a>')
    parts.append('</div>')
    return "".join(parts)


@app.route("/lang/<code>")
def set_lang(code):
    from flask import make_response
    resp = make_response(redirect(request.referrer or url_for("dashboard")))
    resp.set_cookie("lang", "en" if code == "en" else "ru", max_age=31536000)
    return resp





@app.route("/login", methods=["GET", "POST"])
def login():
    s = load_settings()
    msg = ""
    if request.method == "POST":
        rip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
        if not login_allowed(rip):
            msg = f'<div class="alert alert-error">{tr("Слишком много попыток. Подожди 15 минут.","Too many attempts. Wait 15 minutes.")}</div>'
        elif hmac.compare_digest(request.form.get("password", ""), s["admin_pass"]):
            login_reset(rip)
            session["auth"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))
        else:
            login_failed(rip)
            msg = f'<div class="alert alert-error">{tr("Неверный пароль","Wrong password")}</div>'
    html = f"""
    <div class="login-box">
    <h2>{tr("Вход в панель","Sign in")}</h2>
    {msg}
    <form method="post">
    <input type="password" name="password" placeholder="Пароль" autofocus>
    <button class="btn btn-primary" type="submit">{tr("Войти","Sign in")}</button>
    </form>
    </div>"""
    return render(html)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def auth_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/tags")
@auth_required
def tags_alias():
    return redirect(url_for("labels_page"))


@app.route("/api/backup/download")
@auth_required
def backup_download():
    """Create a full server backup and stream it (contains private keys)."""
    from flask import send_file
    try:
        r = subprocess.run(["bash", BACKUP_SCRIPT, "create"],
                           capture_output=True, text=True, timeout=60)
        path = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else ""
        if not path or not os.path.exists(path):
            return ("backup failed: " + (r.stderr or "no output")[-300:], 500)
        return send_file(path, as_attachment=True, download_name=os.path.basename(path),
                         mimetype="application/gzip")
    except Exception as e:
        return ("backup error: " + str(e), 500)


@app.route("/api/backup/restore", methods=["POST"])
@auth_required
def backup_restore():
    """Restore a server from an uploaded backup tarball."""
    import tempfile
    f = request.files.get("backup")
    if not f:
        return ("no file", 400)
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        f.save(tmp.name)
        r = subprocess.run(["bash", BACKUP_SCRIPT, "restore", tmp.name],
                           capture_output=True, text=True, timeout=120)
        out = html_lib.escape((r.stdout + r.stderr)[-1200:])
        return render(f'''<div class="container">{nav("settings")}<div class="card">
        <h2>{tr("Восстановление","Restore")}</h2>
        <pre style="white-space:pre-wrap;font-size:.8em;background:var(--bg);padding:12px;border-radius:8px">{out}</pre>
        <a href="/settings" class="btn btn-sm">{tr("← к настройкам","← back to settings")}</a></div></div>''')
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# ── ttyd web-terminal for Keenetic routers (over WG tunnel) ─────────────────
# Router runs ttyd (web pty) bound to its tunnel IP, firewalled to the panel
# only. Panel reverse-proxies HTTP + bridges the websocket so the browser gets
# a full shell behind NAT without SSH. (awg-manager-style, but over our tunnel.)
def _ttyd_upstream(cid):
    acc = load_settings().get("router_access", {}).get(cid, {})
    ip = (acc.get("ttyd_ip") or acc.get("ssh_ip") or "").strip()
    if not ip:
        client = next((c for c in get_clients() if c.get("client_id") == cid), None)
        ip = (client or {}).get("tunnel_ip_v4", "").split("/")[0]
    port = str(acc.get("ttyd_port", "7681") or "7681")
    token = acc.get("ttyd_token", "")
    return ip, port, token


def _ttyd_auth_header(token):
    import base64
    return "Basic " + base64.b64encode(("phobos:" + token).encode()).decode()


@app.route("/ttyd/<cid>/", defaults={"subpath": ""})
@app.route("/ttyd/<cid>/<path:subpath>", methods=["GET", "POST"])
@auth_required
def ttyd_proxy(cid, subpath):
    import urllib.request, urllib.error
    ip, port, token = _ttyd_upstream(cid)
    if not ip:
        return ("ttyd: tunnel IP unknown", 502)
    url = f"http://{ip}:{port}/ttyd/{cid}/{subpath}"
    data = request.get_data() if request.method == "POST" else None
    req = urllib.request.Request(url, data=data, method=request.method,
                                 headers={"Authorization": _ttyd_auth_header(token)})
    try:
        r = urllib.request.urlopen(req, timeout=12)
        body = r.read()
        ct = r.headers.get("Content-Type", "text/html")
        return (body, r.status, {"Content-Type": ct})
    except urllib.error.HTTPError as e:
        return (e.read(), e.code, {"Content-Type": e.headers.get("Content-Type", "text/plain")})
    except Exception as e:
        return (f"ttyd proxy error: {e}", 502)


if sock:
    @sock.route("/ttyd/<cid>/ws")
    def ttyd_ws(ws, cid):
        import threading
        if not session.get("auth"):   # WS routes bypass @auth_required — gate here
            return
        try:
            import websocket as _wsclient
        except Exception:
            ws.send("ttyd bridge: websocket-client not installed (phobos-update dev)\r\n")
            return
        ip, port, token = _ttyd_upstream(cid)
        if not ip:
            return
        try:
            up = _wsclient.create_connection(
                f"ws://{ip}:{port}/ttyd/{cid}/ws",
                header=["Authorization: " + _ttyd_auth_header(token)],
                subprotocols=["tty"], timeout=12)
        except Exception:
            return
        stop = {"v": False}

        def up_to_browser():
            try:
                while not stop["v"]:
                    opcode, data = up.recv_data(True)
                    if data is None:
                        break
                    ws.send(data if isinstance(data, (bytes, bytearray)) else data)
            except Exception:
                pass
            stop["v"] = True

        t = threading.Thread(target=up_to_browser, daemon=True)
        t.start()
        try:
            while not stop["v"]:
                msg = ws.receive(timeout=30)
                if msg is None:
                    continue
                if isinstance(msg, (bytes, bytearray)):
                    up.send_binary(msg)
                else:
                    up.send(msg)
        except Exception:
            pass
        finally:
            stop["v"] = True
            try:
                up.close()
            except Exception:
                pass


@app.route("/console/router/<cid>")
@auth_required
def ttyd_console(cid):
    ip, port, token = _ttyd_upstream(cid)
    ready = bool(ip and token)
    note = "" if ready else tr(
        "ttyd-терминал не настроен. Включи его кнопкой ниже (нужен запуск phobos-ttyd на роутере).",
        "ttyd terminal not configured. Enable it below (run phobos-ttyd on the router).")
    if ready:
        body = f'<iframe src="/ttyd/{cid}/" style="width:100%;height:72vh;border:1px solid var(--border);border-radius:8px;background:#000"></iframe>'
    else:
        body = (f'<div class="alert alert-warn">{note}</div>'
                f'<form method="post" action="/console/router/{cid}/enable">'
                f'<button class="btn btn-primary" type="submit">⌨️ {tr("Включить терминал на роутере","Enable terminal on router")}</button></form>')
    return render(f'''<div class="container">{nav('clients')}<div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0;border:0;padding:0">🖥️ {tr("Терминал","Terminal")} {_html_attr(cid)} {hlp("Полноценный shell роутера в браузере через ttyd. Работает за NAT по WG-туннелю (без SSH). ttyd слушает только панель.", "Full router shell in the browser via ttyd. Works behind NAT over the WG tunnel (no SSH). ttyd is reachable only by the panel.")}</h2>
      <a href="/clients" class="btn btn-sm" style="background:#475569">{tr("Назад","Back")}</a>
    </div>
    {body}
    </div></div>''')


@app.route("/console/router/<cid>/enable", methods=["POST"])
@auth_required
def ttyd_enable(cid):
    import secrets
    s = load_settings()
    ra = s.setdefault("router_access", {})
    acc = ra.setdefault(cid, {})
    token = acc.get("ttyd_token") or secrets.token_hex(12)
    client = next((c for c in get_clients() if c.get("client_id") == cid), None)
    tip = acc.get("ttyd_ip") or acc.get("ssh_ip") or (client or {}).get("tunnel_ip_v4", "").split("/")[0]
    acc.update({"ttyd_token": token, "ttyd_ip": tip, "ttyd_port": acc.get("ttyd_port", "7681")})
    save_settings(s)
    srv_tip = server_tunnel_ip()
    panel = f"http://{srv_tip}:{request.host.split(':')[-1] if ':' in request.host else '8443'}"
    cmd = f"curl -fsSL {panel}/router/phobos-ttyd.sh | sh -s {cid} {token} {srv_tip}"
    return render(f'''<div class="container">{nav('clients')}<div class="card">
    <h2>⌨️ {tr("Включение терминала","Enable terminal")} — {_html_attr(cid)}</h2>
    <p>{tr("Выполни ОДНУ команду на роутере (SSH/консоль Entware) — поставит ttyd и откроет порт только для панели:","Run ONE command on the router (Entware SSH/console) — installs ttyd and opens the port only to the panel:")}</p>
    <textarea readonly onclick="this.select()" style="width:100%;height:60px;font:13px Menlo,monospace;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px">{cmd}</textarea>
    <p style="font-size:.85em;color:var(--muted)">{tr("После запуска вернись на страницу терминала — появится shell в браузере.","After running it, return to the terminal page — the browser shell appears.")}</p>
    <a href="/console/router/{cid}" class="btn btn-primary btn-sm">{tr("← к терминалу","← to terminal")}</a>
    </div></div>''')


@app.route("/router/phobos-ttyd.sh")
def serve_ttyd_script():
    """Unauthenticated: routers fetch the ttyd setup script over the tunnel.
    Script carries no secrets (token passed as arg by the operator)."""
    for p in ("/opt/Phobos/repo/client/templates/phobos-ttyd.sh",
              "/opt/Phobos/www/phobos-ttyd.sh"):
        if os.path.exists(p):
            return (open(p).read(), 200, {"Content-Type": "text/x-shellscript"})
    return ("phobos-ttyd.sh not found", 404)


@app.route("/")
@auth_required
def dashboard():
    return redirect(url_for("sessions_page"))


@app.route("/sessions")
@auth_required
def sessions_page():
    s = load_settings()
    labels = s.get("labels", {})
    sessions = get_active_sessions()
    # Online = fresh handshake on ANY server (router may be on a backup)
    online_all = set()
    for _pub, _info in get_wg_peers().items():
        if is_peer_online(_info.get("latest handshake", "")):
            online_all.add(_pub)
    for _ip, _hs in server_handshakes_cache.items():
        for _pub, _ts in _hs.items():
            if _ts and (time.time() - _ts) < 180:
                online_all.add(_pub)

    rows = ""
    online_count = 0
    for sess in sessions:
        online = sess["public_key"] in online_all
        if online:
            online_count += 1
        status = '<span class="badge badge-on">Online</span>' if online else '<span class="badge badge-off">Offline</span>'
        real_ip = sess["real_ip"]
        label = labels.get(sess.get("tunnel_ip", ""), "") or labels.get(real_ip, "")
        disp = client_display_name(sess["client_id"], s)
        disp_html = html_lib.escape(disp)
        client_cell = disp_html if disp == sess["client_id"] else f'{disp_html}<div style="font-size:.78em;color:var(--muted)">{sess["client_id"]}</div>'

        rows += f"""<tr>
        <td>{client_cell}</td>
        <td>{sess['tunnel_ip']}</td>
        <td>{real_ip}</td>
        <td>{('<b>' + label + '</b>') if label else '—'}</td>
        <td>{sess['handshake']}</td>
        <td>{sess['rx']} / {sess['tx']}</td>
        <td>{status}</td>
        <td style="display:flex;gap:4px;align-items:center"><a href="/kick/{sess['public_key']}" class="btn btn-danger btn-sm">{tr("Отключить","Kick")}</a>{hlp("Принудительно разорвать текущую сессию клиента (сбросить WG-пир). Клиент переподключится автоматически.","Force-drop the client current session (reset the WG peer). The client reconnects automatically.")}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="8" style="text-align:center;color:var(--muted)">{tr("Нет активных сессий","No active sessions")}</td></tr>'

    html = f"""
    <div class="container">
    {nav('sessions', online_count)}
    <div class="card">
    <h2>{tr("Активные сессии","Active sessions")}</h2>
    <table>
    <tr><th>Клиент</th><th>VPN IP</th><th>Real IP</th><th>Метка</th><th>Handshake</th><th>RX / TX</th><th>Статус</th><th></th></tr>
    {rows}
    </table>
    </div>
    </div>"""
    return render(html)


@app.route("/kick/<path:pub_key>")
@auth_required
def kick(pub_key):
    kick_peer(pub_key)
    return redirect(url_for("sessions_page"))


def _html_attr(value):
    return html_lib.escape(str(value or ""), quote=True)


def _terminal_button(url, title):
    return (f'<a href="{_html_attr(url)}" class="btn btn-sm" '
            f'style="background:#334155" title="{_html_attr(title)}">🖥️</a>')


@app.route("/clients", methods=["GET", "POST"])
@auth_required
def clients_page():
    s = load_settings()
    subs = s.get("subscriptions", {})
    msg = ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            if name and re.match(r"^[a-zA-Z0-9_-]+$", name):
                ok, rep = create_client_cli(name)
                if ok:
                    msg = f'<div class="alert alert-ok">{rep}</div>'
                else:
                    msg = f'<div class="alert alert-error">{rep}</div>'
            else:
                msg = '<div class="alert alert-error">Имя: буквы, цифры, _ и -</div>'

        elif action == "delete":
            client_id = request.form.get("client_id", "").strip()
            if client_id:
                ok, rep = delete_client_cli(client_id)
                if ok:
                    msg = f'<div class="alert alert-ok">{rep}</div>'
                else:
                    msg = f'<div class="alert alert-error">{rep}</div>'

        elif action == "purge_orphan":
            public_key = request.form.get("public_key", "").strip()
            ok, rep = purge_orphan_peer(public_key)
            msg = f'<div class="alert {"alert-ok" if ok else "alert-error"}">{rep}</div>'

        elif action == "toggle_warp_client":
            client_id = request.form.get("client_id", "").strip()
            desired = request.form.get("desired", "").strip() == "on"
            if client_id:
                ok, rep = warp_toggle_client(client_id, desired)
                msg = f'<div class="alert {"alert-ok" if ok else "alert-error"}">{rep}</div>'

        elif action == "toggle_warp_client":
            client_id = request.form.get("client_id", "").strip()
            desired = request.form.get("desired", "").strip() == "on"
            if client_id:
                ok, rep = warp_toggle_client(client_id, desired)
                msg = f'<div class="alert {"alert-ok" if ok else "alert-error"}">{rep}</div>'

        elif action == "rename_client":
            client_id = request.form.get("client_id", "").strip()
            new_name = request.form.get("display_name", "").strip()
            if client_id:
                aliases = s.setdefault("client_aliases", {})
                if new_name:
                    if not re.match(r"^[\w. -]{1,64}$", new_name):
                        msg = f'<div class="alert alert-error">{tr("Имя: буквы, цифры, пробел, _, -, точка.", "Name: letters, digits, space, _, -, dot.")}</div>'
                    else:
                        aliases[client_id] = new_name
                        save_settings(s)
                        msg = f'<div class="alert alert-ok">{tr("Имя сохранено:", "Name saved:")} {html_lib.escape(new_name)}</div>'
                else:
                    aliases.pop(client_id, None)
                    save_settings(s)
                    msg = f'<div class="alert alert-ok">{tr("Псевдоним очищен.", "Alias cleared.")}</div>'

        elif action == "toggle_notify":
            client_id = request.form.get("client_id", "").strip()
            if client_id:
                cn = s.setdefault("client_notify", {})
                cn[client_id] = not cn.get(client_id, True)
                save_settings(s)
                st = "вкл" if cn[client_id] else "выкл"
                msg = f'<div class="alert alert-ok">Уведомления {client_id}: {st}</div>'

        elif action == "set_limit":
            client_id = request.form.get("client_id", "").strip()
            raw = request.form.get("limit_mbit", "").strip()
            if client_id and (raw == "" or raw.isdigit()):
                lim = s.setdefault("speed_limits", {})
                if raw in ("", "0"):
                    lim.pop(client_id, None)
                else:
                    lim[client_id] = int(raw)
                save_settings(s)
                ok, rep = apply_speed_limits()
                msg = f'<div class="alert {"alert-ok" if ok else "alert-error"}">{html_lib.escape(rep)}</div>'

        elif action == "set_expiry":
            client_id = request.form.get("client_id", "").strip()
            expiry = request.form.get("expiry", "").strip()
            if client_id:
                if client_id not in subs:
                    subs[client_id] = {}
                subs[client_id]["expiry"] = expiry
                subs[client_id].pop("locked", None)
                subs[client_id].pop("warn3", None)
                subs[client_id].pop("warn1", None)
                save_settings(s)
                msg = f'<div class="alert alert-ok">Срок для {client_id} обновлён</div>'

        elif action == "push_config":
            client_id = request.form.get("client_id", "").strip()
            res = push_config_to_router(client_id)
            if res["status"] == "ok":
                msg = f'<div class="alert alert-ok">{res["msg"]}</div>'
            else:
                msg = f'<div class="alert alert-ok">{client_id}: saved — router will pull config within ~2 min (SSH not needed for NAT routers)</div>'

        elif action == "assign_server":
            client_id = request.form.get("client_id", "").strip()
            server_ip = request.form.get("server_ip", "").strip()
            if client_id and server_ip:
                # 1. Find client public key + tunnel IP for WG peer
                client_meta = None
                for c in get_clients():
                    if c.get("client_id") == client_id:
                        client_meta = c
                        break
                errors = []
                # 2. Add WG peer on target server
                if client_meta:
                    pub = client_meta.get("public_key", "")
                    tip = client_meta.get("tunnel_ip_v4", "").split("/")[0]
                    if pub and tip:
                        allowed = f"{tip}/32"
                        peer_res = add_peer_to_server(server_ip, pub, allowed)
                        if peer_res.get("status") != "ok":
                            errors.append(f"Peer add: {peer_res.get('msg', 'fail')}")
                # 3. Save assignment
                ca = s.get("client_assignments", {})
                ca[client_id] = server_ip
                s["client_assignments"] = ca
                save_settings(s)
                fanout_router_config(client_id)  # push conf to all servers (tunnel pull)
                # 4. Router applies via pull (~15s). No synchronous SSH push:
                #    NAT routers can't be reached, and the SSH attempt blocked
                #    the click for seconds. Pull channel handles the apply.
                if errors:
                    msg = f'<div class="alert alert-error">{client_id} → {server_ip}: {"; ".join(errors)}</div>'
                else:
                    msg = f'<div class="alert alert-ok">{client_id} → {server_ip} ✓ (saved — router applies within ~15s)</div>'

    clients = get_clients(include_orphans=True)
    peers = get_wg_peers()
    online_pubs = set()
    for pub, info in peers.items():
        if is_peer_online(info.get("latest handshake", "")):
            online_pubs.add(pub)

    all_srv = get_all_servers_ordered()
    assignments = s.get("client_assignments", {})
    assignments_notify = s.get("client_notify", {})
    aliases = s.get("client_aliases", {})
    warp_cfg = get_warp_settings(s)
    warp_enabled_clients = set(str(x).strip() for x in s.get("warp_clients", []) if str(x).strip())
    warp_state = warp_status()
    # Online = fresh handshake on ANY server (truthful during failover/transition)
    online_all = set(online_pubs)
    for _sv in all_srv:
        if _sv.get("ip") == SERVER_IP:
            continue
        for _pub, _ts in remote_handshakes(_sv["ip"]).items():
            if _ts and (time.time() - _ts) < 180:
                online_all.add(_pub)

    limits = s.get("speed_limits", {})
    rows = ""
    today = datetime.now().date()
    for c in clients:
        cid = c.get("client_id", "")
        disp = str(aliases.get(cid, "") or "").strip() or cid
        disp_input = _html_attr(aliases.get(cid, ""))
        disp_html = html_lib.escape(disp)
        pub = c.get("public_key", "")
        ip = c.get("tunnel_ip_v4", "")
        is_orphan = bool(c.get("_orphan"))
        created = c.get("created_at", "")[:10]
        is_online = pub in online_all
        status = '<span class="badge badge-on">Online</span>' if is_online else '<span class="badge badge-off">Offline</span>'
        if is_orphan:
            status += ' <span class="badge badge-warn">orphan</span>'

        sub = subs.get(cid, {})
        expiry = sub.get("expiry", "")
        locked = sub.get("locked", False)
        expiry_badge = ""
        if expiry:
            try:
                exp_date = datetime.strptime(expiry, "%Y-%m-%d").date()
                days = (exp_date - today).days
                if locked:
                    expiry_badge = '<span class="expiry-badge badge-lock">expired</span>'
                elif days <= 1:
                    expiry_badge = f'<span class="expiry-badge badge-warn">{days}d</span>'
                elif days <= 3:
                    expiry_badge = f'<span class="expiry-badge badge-warn">{days}d</span>'
                else:
                    expiry_badge = f'<span class="expiry-badge badge-on">{days}d</span>'
            except ValueError:
                pass

        assigned_ip = assignments.get(cid, SERVER_IP)
        srv_opts = ""
        for sv in all_srv:
            sel = " selected" if sv["ip"] == assigned_ip else ""
            label = f'{sv["ip"]} (Primary)' if sv.get("is_primary") else sv["ip"]
            srv_opts += f'<option value="{sv["ip"]}"{sel}>{label}</option>'

        set_lbl = tr("Задать", "Set")
        h_set = hlp("Выбери сервер выхода для этого роутера и нажми «Задать». Роутер сам переключится за ~15 секунд. Кнопку Push нажимать НЕ нужно — конфигурация подтягивается автоматически.",
                    "Pick the exit server for this router and press Set. The router switches itself within ~15 seconds. You do NOT need a Push button — the config is pulled automatically.")
        h_exp = hlp("Дата окончания подписки клиента. После этой даты клиент автоматически блокируется. Оставь пустым — без срока.",
                    "Client subscription expiry date. After this date the client is locked automatically. Leave empty for no expiry.")
        h_del = hlp("Безвозвратно удалить клиента, его ключи и конфигурацию. Отменить нельзя.",
                    "Permanently delete the client, its keys and config. Cannot be undone.")
        del_confirm = tr("Удалить " + cid + "?", "Delete " + cid + "?")
        _notify = assignments_notify.get(cid, True)
        notify_icon = "🔔" if _notify else "🔕"
        notify_bg = "#4f46e5" if _notify else "#64748b"
        notify_ttl = tr("Уведомления в Telegram включены — нажми, чтобы выключить", "Telegram notifications ON — click to turn off") if _notify else tr("Уведомления выключены — нажми, чтобы включить", "Notifications OFF — click to turn on")
        term_btn = ""
        if not is_orphan:
            term_btn = _terminal_button(f"/terminal/router/{cid}", tr("SSH терминал роутера", "Router SSH terminal"))
            rci_btn = (f'<a href="/rci/router/{cid}" class="btn btn-sm" style="background:#7c3aed" '
                       f'title="{_html_attr(tr("RCI-консоль Keenetic (ndmc через KeenDNS, за NAT)", "Keenetic RCI console (ndmc via KeenDNS, behind NAT)"))}">🛠️</a>')
            tty_btn = (f'<a href="/console/router/{cid}" class="btn btn-sm" style="background:#0891b2" '
                       f'title="{_html_attr(tr("Терминал роутера в браузере (ttyd по туннелю, за NAT)", "Router terminal in browser (ttyd over tunnel, behind NAT)"))}">⌨️</a>')
            term_btn = term_btn + " " + rci_btn + " " + tty_btn
        warp_on = cid in warp_enabled_clients
        warp_mode_ok = warp_cfg.get("mode") == "egress"
        warp_btn_bg = "#0f766e" if warp_on else "#475569"
        warp_btn_lbl = "WARP ON" if warp_on else "WARP OFF"
        warp_btn_title = tr("Индивидуальный WARP для этого клиента", "Per-client WARP for this client")
        if not warp_mode_ok:
            warp_btn_bg = "#334155"
            warp_btn_title = tr("Per-client WARP работает только в режиме egress", "Per-client WARP works only in egress mode")
        elif warp_state.get("service") != "active":
            warp_btn_title = tr("Сохранит выбор. Применится после включения WARP egress.", "Saves choice. Applies after WARP egress is enabled.")
        server_cell = f"""
            <form method="post">
            <input type="hidden" name="action" value="assign_server">
            <input type="hidden" name="client_id" value="{cid}">
            <select name="server_ip" title="{tr("Сервер выхода","Exit server")}">{srv_opts}</select>
            <button class="btn btn-primary btn-sm" type="submit">{set_lbl}</button>
            {h_set}
            </form>
        """
        expiry_cell = f"""
            <form method="post">
            <input type="hidden" name="action" value="set_expiry">
            <input type="hidden" name="client_id" value="{cid}">
            <input type="date" name="expiry" value="{expiry}" title="{tr("Срок подписки","Expiry")}">
            <button class="btn btn-primary btn-sm" type="submit">{set_lbl}</button>
            {h_exp}
            </form>
        """
        actions_cell = f"""
            <form method="post" title="{notify_ttl}">
            <input type="hidden" name="action" value="toggle_notify">
            <input type="hidden" name="client_id" value="{cid}">
            <button class="btn btn-sm" style="background:{notify_bg}" type="submit">{notify_icon}</button>
            </form>
            <form method="post" title="{_html_attr(warp_btn_title)}">
            <input type="hidden" name="action" value="toggle_warp_client">
            <input type="hidden" name="client_id" value="{cid}">
            <input type="hidden" name="desired" value="{'off' if warp_on else 'on'}">
            <button class="btn btn-sm" style="background:{warp_btn_bg}" type="submit">🌀 {"ON" if warp_on else "WARP"}</button>
            </form>
            <form method="post" onsubmit="return confirm('{del_confirm}')">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="client_id" value="{cid}">
            <button class="btn btn-danger btn-sm" type="submit">{tr("Удалить", "Del")}</button>
            </form>
            <a href="/client/{cid}/phone/android" class="btn btn-sm" style="background:#16a34a" title="Android / PhobosWG">📱</a>
            <a href="/client/{cid}/phone/ios" class="btn btn-sm" style="background:#475569" title="iPhone / iOS WireGuard">🍎</a>
            <a href="/client/{cid}/router-config" class="btn btn-sm" style="background:#334155" title="{tr("Команда установки роутера", "Router install command")}">📡</a>
            {term_btn}
            {h_del}
        """
        if is_orphan:
            server_cell = f'<span style="color:var(--warn)">{tr("Сиротский peer в wg0", "Orphan peer in wg0")}</span> {hlp("Панель видит WireGuard peer и handshake, но папка клиента и metadata отсутствуют. Такое бывает после ручной чистки или старого бага. Можно оставить как есть, либо очистить peer кнопкой Purge.", "Panel sees live WireGuard peer and handshake, but client folder and metadata are missing. This can happen after manual cleanup or old bug. You can keep it, or remove peer with Purge button.")}'
            expiry_cell = '<span style="color:var(--muted)">—</span>'
            actions_cell = f"""
            <form method="post" title="{_html_attr(tr("Точечный WARP для этого peer", "Per-peer WARP for this peer"))}">
            <input type="hidden" name="action" value="toggle_warp_client">
            <input type="hidden" name="client_id" value="{cid}">
            <input type="hidden" name="desired" value="{'off' if warp_on else 'on'}">
            <button class="btn btn-sm" style="background:{warp_btn_bg}" type="submit">🌀 {"ON" if warp_on else "WARP"}</button>
            </form>
            <a href="/kick/{pub}" class="btn btn-danger btn-sm">{tr("Отключить", "Kick")}</a>
            <form method="post" onsubmit="return confirm('{tr("Удалить orphan peer?", "Delete orphan peer?")}')">
            <input type="hidden" name="action" value="purge_orphan">
            <input type="hidden" name="public_key" value="{pub}">
            <button class="btn btn-sm" style="background:#b45309" type="submit">{tr("Purge", "Purge")}</button>
            </form>
            """
        client_cell = html_lib.escape(disp)
        if disp != cid:
            client_cell += f'<div style="font-size:.78em;color:var(--muted)">{cid}</div>'
        rename_box = f"""
            <form method="post">
            <input type="hidden" name="action" value="rename_client">
            <input type="hidden" name="client_id" value="{cid}">
            <input type="text" name="display_name" value="{_html_attr('' if disp == cid else disp)}" placeholder="{tr('Имя в панели','Display name')}" style="width:130px">
            <button class="btn btn-sm" style="background:#475569" type="submit">{tr("Имя","Name")}</button>
            </form>
        """
        lim = str(limits.get(cid, "") or "")
        rate = client_rates.get(pub)
        speed = (f'<span class="cspeed" title="{tr("Скорость сейчас","Current speed")}">↓{rate[0]:.1f} ↑{rate[1]:.1f} {tr("Мбит/с","Mbit/s")}</span>' if rate else "")
        limit_cell = "" if is_orphan else f"""
            <form method="post" title="{tr("Лимит скорости, Мбит/с (0 или пусто — без лимита)","Speed limit, Mbit/s (0/empty = none)")}">
            <input type="hidden" name="action" value="set_limit">
            <input type="hidden" name="client_id" value="{cid}">
            <input type="number" name="limit_mbit" value="{_html_attr(lim)}" min="0" max="10000" placeholder="{tr("без лимита","no limit")}" style="width:96px">
            <span class="cunit">{tr("Мбит/с","Mbit/s")}</span>
            <button class="btn btn-primary btn-sm" type="submit">{set_lbl}</button>
            </form>"""
        rows += f"""<div class="ccard">
        <div class="ctop"><span class="cname">{client_cell}</span> <span class="cip">{ip}</span> {status} {expiry_badge} {f'<span class="badge badge-lock">≤{_html_attr(lim)} Mbit</span>' if lim and lim != "0" else ""} {speed}</div>
        <div class="cctl">{server_cell}{expiry_cell}{limit_cell}{rename_box}</div>
        <div class="cact">{actions_cell}</div>
        </div>"""
    if not rows:
        rows = f'<p style="text-align:center;color:var(--muted)">{tr("Пока нет клиентов. Создай первого клиента выше.","No clients yet. Create first client above.")}</p>'

    page_html = f"""
    <div class="container">
    {nav('clients')}
    {msg}
    <div class="card">
    <h2>{tr("VPN-клиенты", "VPN Clients")}</h2>
    <form method="post" class="form-row" style="margin-bottom:16px">
    <input type="hidden" name="action" value="add">
    <input type="text" name="name" placeholder="{tr('Имя нового клиента', 'New client name')}" pattern="[A-Za-z0-9_\\-]+" required>
    <button class="btn btn-primary" type="submit">{tr("Добавить", "Add")}</button>
    {hlp("Создать нового VPN-клиента (роутер/устройство). Имя — латиница, цифры, _ и -. После создания выдай команду установки на роутер.", "Create a new VPN client (router/device). Name: letters, digits, _ and -. After creation, run the install command on the router.")}
    </form>
    <p style="font-size:.82em;color:var(--muted);margin:-6px 0 12px">⚡ {tr("Скорость на устройстве клиента (с включённым VPN)","Speed on the client device (VPN on)")}: <code>http://{server_tunnel_ip()}:{panel_port()}/speedtest</code></p>
    <div class="clist">{rows}</div>
    </div>
    </div>"""
    return render(page_html)


@app.route("/labels", methods=["GET", "POST"])
@auth_required
def labels_page():
    s = load_settings()
    msg = ""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            ip = request.form.get("ip", "").strip()
            label = request.form.get("label", "").strip()
            if ip and label:
                s["labels"][ip] = label
                save_settings(s)
                msg = f'<div class="alert alert-ok">Метка добавлена: {ip} → {label}</div>'
        elif action == "delete":
            ip = request.form.get("ip", "").strip()
            s["labels"].pop(ip, None)
            save_settings(s)
            msg = f'<div class="alert alert-ok">Метка удалена</div>'

    labels = s.get("labels", {})
    rows = ""
    for ip, label in sorted(labels.items()):
        rows += f"""<tr>
        <td>{ip}</td><td>{label}</td>
        <td><form method="post" style="display:inline">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="ip" value="{ip}">
        <button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('Удалить метку?')">Удалить</button>
        </form></td></tr>"""

    html = f"""
    <div class="container">
    {nav('labels')}
    {msg}
    <div class="card">
    <h2>{tr("Метки (по IP)","Labels (by IP)")} {hlp("Человекочитаемые имена для IP/туннелей — показываются в Сессиях вместо голого адреса.","Human-readable names for IPs/tunnels — shown in Sessions instead of the raw address.")}</h2>
    <p style="color:var(--muted);font-size:.85em;margin-bottom:12px">Привяжите понятное имя (квартира, офис, дача) к внешнему IP адресу роутера. Метка отображается в таблице сессий и в Telegram уведомлениях вместо голого IP.</p>
    <form method="post" class="form-row" style="margin-bottom:16px">
    <input type="hidden" name="action" value="add">
    <input type="text" name="ip" placeholder="Real IP" required>
    <input type="text" name="label" placeholder="{tr('Имя объекта','Object name')}" required>
    <button class="btn btn-primary" type="submit">{tr("Добавить","Add")}</button>
    </form>
    <table>
    <tr><th>Real IP</th><th>Метка</th><th></th></tr>
    {rows}
    </table>
    </div>
    </div>"""
    return render(html)


@app.route("/settings", methods=["GET", "POST"])
@auth_required
def settings_page():
    s = load_settings()
    msg = ""
    if request.method == "POST" and request.form.get("action") in (
        "update", "rollback", "check", "save_token",
        "warp_save", "warp_enable", "warp_disable", "warp_status"
    ):
        _act = request.form.get("action")
        # subscriber token may be pasted in the version card -> persist for beta/dev
        _tok = request.form.get("gh_token", "").strip()
        if _tok:
            save_gh_token(_tok)
        warp_cfg = apply_warp_form(s)
        save_settings(s)
        if _act == "save_token":
            _out = tr("Токен подписчика сохранён. Теперь можно переключаться на beta/dev.",
                      "Subscriber token saved. You can now switch to beta/dev.") if _tok else \
                   tr("Поле токена пустое.", "Token field is empty.")
        elif _act == "warp_save":
            _out = tr("WARP настройки сохранены.", "WARP settings saved.")
        elif _act == "update":
            _out = run_update(request.form.get("target", "").strip() or "main")
        elif _act == "check":
            _out = run_update("--check")
        elif _act == "warp_enable":
            if warp_cfg["mode"] == "relay":
                _out = run_warp("enable", "relay", warp_cfg["profile_source"],
                                warp_cfg["relay_ports"], warp_cfg["relay_target"])
            else:
                _out = run_warp("enable", "egress", warp_cfg["profile_source"])
                for _cid in [str(x).strip() for x in s.get("warp_clients", []) if str(x).strip()]:
                    _cl = next((c for c in get_clients() if c.get("client_id") == _cid), None)
                    _tip = ((_cl or {}).get("tunnel_ip_v4") or "").split("/")[0].strip()
                    if _tip:
                        run_warp("client-enable", _tip)
        elif _act == "warp_disable":
            _out = run_warp("disable")
        elif _act == "warp_status":
            _out = run_warp("status")
        else:
            _out = run_update("--rollback")
        s = load_settings()
        return render(f'''<div class="container">{nav("settings")}<div class="card">
        <h2>{tr("Результат", "Result")}</h2>
        <pre style="white-space:pre-wrap;font-size:.8em;background:var(--bg);padding:12px;border-radius:8px">{_out}</pre>
        <a href="/settings" class="btn btn-sm">{tr("← к настройкам", "← back to settings")}</a></div></div>''')
    if request.method == "POST" and request.form.get("action") in (
        "domain_set", "domain_remove", "endpoints_save",
        "guard_enable", "guard_disable", "guard_update"
    ):
        _act = request.form.get("action")
        if _act == "domain_set":
            ok, _out = run_server_script("phobos-domain.sh", "set",
                                         request.form.get("domain", "").strip(),
                                         request.form.get("domain_email", "").strip(), timeout=300)
        elif _act == "domain_remove":
            ok, _out = run_server_script("phobos-domain.sh", "remove")
        elif _act == "endpoints_save":
            ok, _out = save_client_endpoints(request.form)
        else:
            ok, _out = run_server_script("phobos-guard.sh", _act.split("_", 1)[1], timeout=300)
        cls = "alert-ok" if ok else "alert-error"
        return render(f'''<div class="container">{nav("settings")}<div class="card">
        <h2>{tr("Результат", "Result")}</h2>
        <div class="alert {cls}">{tr("Готово", "Done") if ok else tr("Ошибка", "Error")}</div>
        <pre style="white-space:pre-wrap;font-size:.8em;background:var(--bg);padding:12px;border-radius:8px">{html_lib.escape(_out)}</pre>
        <a href="/settings" class="btn btn-sm btn-primary">{tr("← к настройкам", "← back to settings")}</a></div></div>''')
    if request.method == "POST" and request.form.get("action") == "save_obf":
        masking = request.form.get("obf_masking", "AUTO").strip().upper()
        if masking not in ("AUTO", "STUN", "NONE"):
            masking = "AUTO"
        s["obf_params"] = {
            "masking": masking,
            "max_dummy": request.form.get("obf_max_dummy", "4").strip() or "4",
            "idle": request.form.get("obf_idle", "300").strip() or "300",
        }
        save_settings(s)
        pushed = 0
        for c in get_clients():
            try:
                fanout_router_config(c.get("client_id", ""))
                pushed += 1
            except Exception:
                pass
        msg = f'<div class="alert alert-ok">{tr("Параметры обфускатора сохранены и отправлены на роутеры", "Obfuscator params saved and pushed to routers")} ({pushed})</div>'
    elif request.method == "POST":
        new_pass = request.form.get("admin_pass", "").strip()
        if new_pass:
            s["admin_pass"] = new_pass
        s["tg_bot_token"] = request.form.get("tg_bot_token", "").strip()
        s["tg_chat_id"] = request.form.get("tg_chat_id", "").strip()
        try:
            s["monitor_interval"] = max(10, int(request.form.get("monitor_interval", 30)))
        except ValueError:
            pass
        save_settings(s)
        msg = '<div class="alert alert-ok">Настройки сохранены</div>'

    warp_cfg = get_warp_settings(s)
    custom_warp_profile = read_custom_warp_profile()
    warp_license_key = read_warp_license_key()
    warp = warp_status()
    warp_service = warp.get("service", "unknown")
    warp_state = tr("включён", "enabled") if warp.get("enabled") else tr("выключен", "disabled")
    warp_subnet = _html_attr(warp.get("subnet", server_wg_network()))
    warp_endpoint = _html_attr(warp.get("endpoint", ""))
    warp_egress = _html_attr(warp.get("egress_ipv4", ""))
    warp_error = _html_attr(warp.get("error", ""))
    warp_mode = _html_attr(warp.get("mode", warp_cfg.get("mode", "egress")))
    warp_profile_source = _html_attr(warp.get("profile_source", warp_cfg.get("profile_source", "free")))
    warp_relay_ports = _html_attr(warp.get("relay_ports", warp_cfg.get("relay_ports", "4500")))
    warp_relay_target = _html_attr(warp.get("relay_target", warp_cfg.get("relay_target", "")))
    warp_client_count = len(warp.get("clients", [])) if isinstance(warp.get("clients", []), list) else len(s.get("warp_clients", []))
    custom_profile_saved = bool(warp.get("custom_profile_saved")) or bool(custom_warp_profile.strip())
    warp_license_saved = bool(warp.get("license_key_saved")) or bool(warp_license_key.strip()) or bool(warp_cfg.get("license_key", "").strip())

    dom = script_status("phobos-domain.sh")
    guard = script_status("phobos-guard.sh")
    dom_q = tr("Убрать домен?", "Remove domain?")
    dom_remove = (f'<form method="post" style="display:inline" onsubmit="return confirm(\'{dom_q}\')">'
                  f'<input type="hidden" name="action" value="domain_remove">'
                  f'<button class="btn btn-danger btn-sm" type="submit">{tr("Убрать домен", "Remove domain")}</button></form>'
                  if dom.get("domain") else "")
    eps = s.get("endpoints", {})
    ep_rows = "".join(
        f'<div class="form-row"><label>{_html_attr(sv["ip"])}{" ★" if sv.get("is_primary") else ""}</label>'
        f'<input type="text" name="ep_{_html_attr(sv["ip"])}" value="{_html_attr(eps.get(sv["ip"], ""))}" placeholder="{_html_attr(sv["ip"])}" style="width:260px"></div>'
        for sv in get_all_servers_ordered())
    _cu = f"{panel_base_url()}/server/phobos-cascade.sh"
    cascade_cmd = f"SELF_URL={_cu} bash &lt;(curl -kfsSL {_cu}) enable {SERVER_IP} {_load_server_env().get('OBFUSCATOR_PORTS', '2083,5443,993')}"
    extras_html = f"""
    <div class="card">
    <h2>{tr("Домен панели","Panel domain")} {hlp("Панель по адресу https://ваш-домен/ с бесплатным сертификатом Let's Encrypt (nginx на 443). Домен (A-запись) должен указывать на IP этого сервера, порт 80 открыт. Старый адрес http://IP:порт продолжает работать — роутеры и второй сервер ничего не заметят.", "Panel at https://your-domain/ with a free Let's Encrypt certificate (nginx on 443). The domain A record must point to this server, port 80 open. The old http://IP:port keeps working — routers and secondaries notice nothing.")}</h2>
    {f'<p>{tr("Сейчас","Now")}: <a href="https://{_html_attr(dom.get("domain"))}/" target="_blank" rel="noopener"><b>https://{_html_attr(dom.get("domain"))}/</b></a> · {tr("сертификат до","certificate until")} {_html_attr(dom.get("cert_expires") or "—")}</p>' if dom.get("domain") else f'<p style="color:var(--muted)">{tr("Домен не задан.","No domain set.")}</p>'}
    <form method="post" class="form-row" style="margin-top:8px">
      <input type="hidden" name="action" value="domain_set">
      <input type="text" name="domain" placeholder="vpn.example.com" value="{_html_attr(dom.get("domain", ""))}" style="width:240px" required>
      <input type="email" name="domain_email" placeholder="email ({tr("необязательно","optional")})" style="width:220px">
      <button class="btn btn-primary btn-sm" type="submit">{tr("Выпустить сертификат и включить","Issue certificate & enable")}</button>
    </form>
    {dom_remove}
    </div>

    <div class="card">
    <h2>{tr("Адрес для клиентов и каскад","Client address & cascade")} {hlp("Куда подключаются клиенты для каждого сервера. Пусто = IP сервера. Можно вписать домен (A-запись на сервер) — сменится IP, поменяешь только DNS. Каскад: поставь на входной VPS (например, в РФ) ретранслятор командой ниже и впиши сюда IP/домен этого входа — клиенты пойдут вход → этот сервер. Роутеры получат новый адрес сами через pull (~15 с), телефонам нужно заново открыть ссылку/QR.", "Which host clients dial for each server. Empty = server IP. Put a domain (A record) to survive IP changes. Cascade: install the relay on an entry VPS with the command below and put that entry IP/domain here — clients go entry -> this server. Routers get it via pull (~15s); phones must reopen the link/QR.")}</h2>
    <form method="post">
      <input type="hidden" name="action" value="endpoints_save">
      {ep_rows}
      <div class="form-row"><label></label><button class="btn btn-primary btn-sm" type="submit">{tr("Сохранить и отправить роутерам","Save & push to routers")}</button></div>
    </form>
    <p style="font-size:.85em;color:var(--muted);margin:10px 0 6px">{tr("Каскад — выполни на входном VPS (чистый Debian/Ubuntu, root):","Cascade — run on the entry VPS (clean Debian/Ubuntu, root):")}</p>
    <code style="background:var(--bg);padding:8px 12px;border-radius:6px;display:block;font-size:.82em;word-break:break-all">{cascade_cmd}</code>
    <p style="font-size:.8em;color:var(--muted);margin-top:6px">{tr("Отключить: phobos-cascade disable · статус: phobos-cascade status. iOS/обычный WireGuard (порт 51820) через каскад не идёт.","Disable: phobos-cascade disable · status: phobos-cascade status. iOS/plain WireGuard (port 51820) does not go through the cascade.")}</p>
    </div>

    <div class="card">
    <h2>{tr("Защита сервера (сторож)","Server protection (guard)")} {hlp("Блокирует подсети зондов и сканеров РКН до того, как они дойдут до сервера (nftables). Список IP — из проекта Loorrr293/Auto_IPtables, обновляется раз в сутки. Частные сети (LAN, туннель) никогда не блокируются.", "Drops RKN probe/scanner subnets before they reach the server (nftables). IP list from Loorrr293/Auto_IPtables, refreshed daily. Private networks (LAN, tunnel) are never blocked.")}</h2>
    <p>{tr("Статус","Status")}: <b style="color:{'#16a34a' if guard.get("enabled") else '#f59e0b'}">{tr("включён","enabled") if guard.get("enabled") else tr("выключен","disabled")}</b>
       · {tr("подсетей","networks")}: {guard.get("networks", 0)} · {tr("отброшено пакетов","dropped packets")}: {guard.get("dropped_packets", 0)}</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      <form method="post"><input type="hidden" name="action" value="guard_enable"><button class="btn btn-primary btn-sm" type="submit">{tr("Включить","Enable")}</button></form>
      <form method="post"><input type="hidden" name="action" value="guard_update"><button class="btn btn-sm" style="background:#475569" type="submit">{tr("Обновить список","Refresh list")}</button></form>
      <form method="post"><input type="hidden" name="action" value="guard_disable"><button class="btn btn-danger btn-sm" type="submit">{tr("Выключить","Disable")}</button></form>
    </div>
    <p style="font-size:.82em;color:var(--muted);margin-top:10px">{tr("«Прикрывашка» (WARP на выход + Psiphon, автор miha75vu-bit/Flashkeen) — интерактивная, ставится по SSH: <code>bash &lt;(curl -fsSL https://raw.githubusercontent.com/miha75vu-bit/Flashkeen/main/wp)</code>. Она перестраивает выход wg0 — не включай одновременно со встроенным WARP egress ниже.","“Prikryvashka” (WARP egress + Psiphon by miha75vu-bit/Flashkeen) is interactive, run it over SSH: <code>bash &lt;(curl -fsSL https://raw.githubusercontent.com/miha75vu-bit/Flashkeen/main/wp)</code>. It rebuilds wg0 egress — do not combine with the built-in WARP egress below.")}</p>
    </div>
"""

    html = f"""
    <div class="container">
    {nav('settings')}
    {msg}
    <div class="card">
    <h2>{tr("Настройки панели","Panel settings")}</h2>
    <form method="post">
    <div class="form-row"><label>{tr("Пароль панели","Panel password")}</label><input type="password" name="admin_pass" placeholder="{tr('Оставьте пустым','Leave empty')}">{hlp("Новый пароль для входа в эту панель. Оставь пустым — пароль не изменится.","New password to sign in to this panel. Leave empty to keep current.")}</div>
    <div class="form-row"><label>Telegram Token</label><input type="text" name="tg_bot_token" value="{s.get('tg_bot_token','')}">{hlp("Токен Telegram-бота для оповещений (падение/восстановление серверов, подключения, истечение подписок).","Telegram bot token for alerts (server up/down, connections, subscription expiry).")}</div>
    <div class="form-row"><label>Telegram Chat ID</label><input type="text" name="tg_chat_id" value="{s.get('tg_chat_id','')}"></div>
    <div class="form-row"><label>{tr("Интервал (сек)","Interval (s)")}</label><input type="number" name="monitor_interval" value="{s.get('monitor_interval',30)}" min="10">{hlp("Как часто фоновый монитор опрашивает серверы и обновляет статусы/оповещения. Меньше = свежее, но больше нагрузка.","How often the background monitor polls servers and refreshes statuses/alerts. Lower = fresher but more load.")}</div>
    <div class="form-row"><label></label><button class="btn btn-primary" type="submit">{tr("Сохранить","Save")}</button></div>
    </form>
    </div>
    {extras_html}

    <div class="card">
    <h2>{tr("Версия и обновления","Version & updates")} {hlp("Скачивает свежие файлы PCA-слоя (панель + скрипты) с GitHub и перезапускает панель. Ключи WireGuard, server.env и клиенты НЕ трогаются. Пусто или main = последняя версия; можно указать тег (например v1.1.0). Откат восстанавливает предыдущую версию из автоматического бэкапа.", "Fetches the latest PCA files (panel + scripts) from GitHub and restarts the panel. WireGuard keys, server.env and clients are NOT touched. Empty or main = latest; you can pass a tag (e.g. v1.1.0). Rollback restores the previous version from an automatic backup.")}</h2>
    <p>{tr("Установленная версия","Installed version")}: <b style="color:var(--accent)">{panel_version()}</b></p>
    <p style="font-size:.85em;color:var(--muted);margin:4px 0 8px">{tr("Каналы","Channels")}:
      <b style="color:#22c55e">stable</b> — {tr("стабильная","stable")} ·
      <b style="color:#eab308">beta</b> — {tr("тест","testing")} ·
      <b style="color:#f97316">dev</b> — {tr("разработка","development")}.
      {tr("С 1.4.0 все каналы открыты и берутся с git.bobyrev.com (GitHub — запасной). Токен больше не нужен.","Since 1.4.0 all channels are open and served from git.bobyrev.com (GitHub as fallback). No token needed.")}</p>
    <form method="post" class="form-row" style="margin-bottom:8px">
      <input type="hidden" name="action" value="save_token">
      <input type="password" name="gh_token" placeholder="{tr('токен подписчика (для beta/dev)','subscriber token (for beta/dev)')}" style="width:240px" autocomplete="off">
      <button class="btn btn-sm" style="background:#475569" type="submit">{tr("Сохранить токен","Save token")}</button>
      <span style="font-size:.82em;color:{'#22c55e' if gh_token_present() else '#f59e0b'}">{(tr("✓ токен сохранён","✓ token saved") if gh_token_present() else tr("токен не задан — beta/dev недоступны","no token — beta/dev locked"))}</span>
    </form>
    <div class="form-row" style="gap:6px;margin-bottom:8px">
      <form method="post" style="display:inline"><input type="hidden" name="action" value="update"><input type="hidden" name="target" value="stable"><button class="btn btn-sm" style="background:#16a34a" type="submit" onclick="return confirm('{tr("Перейти на стабильную?","Switch to stable?")}')">stable</button></form>
      <form method="post" style="display:inline"><input type="hidden" name="action" value="update"><input type="hidden" name="target" value="beta"><button class="btn btn-sm" style="background:#ca8a04" type="submit" onclick="return confirm('{tr("Перейти на beta?","Switch to beta?")}')">beta</button></form>
      <form method="post" style="display:inline"><input type="hidden" name="action" value="update"><input type="hidden" name="target" value="dev"><button class="btn btn-sm" style="background:#ea580c" type="submit" onclick="return confirm('{tr("Перейти на dev (нестабильно)?","Switch to dev (unstable)?")}')">dev</button></form>
    </div>
    <form method="post" class="form-row">
    <input type="hidden" name="action" value="update">
    <input type="text" name="target" placeholder="stable / beta / dev / v1.2.4" style="width:170px">
    <button class="btn btn-primary" type="submit" onclick="return confirm('{tr("Обновить панель и скрипты?","Update panel and scripts?")}')">{tr("Обновить","Update")}</button>
    </form>
    <form method="post" style="display:inline">
    <input type="hidden" name="action" value="check">
    <button class="btn btn-sm" style="background:#0ea5e9" type="submit">{tr("Проверить обновления","Check for updates")}</button>
    </form>
    <form method="post" style="margin-top:8px">
    <input type="hidden" name="action" value="rollback">
    <button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('{tr("Откатить на предыдущую версию?","Roll back to the previous version?")}')">{tr("Откатить на предыдущую","Rollback")}</button>
    </form>
    </div>

    <div class="card">
    <h2>{tr("Бэкап и восстановление","Backup & restore")} {hlp("Полный бэкап состояния сервера: ключ WireGuard, server.env, все клиенты и ключи, токены, настройки панели (метки, назначения, доступы, токен подписчика). НЕ включает бинарники/пакеты. Восстановление на чистом VPS: сначала turnkey-установка, потом загрузи бэкап здесь — ключ сервера вернётся, клиенты переподключатся без пересоздания. ВНИМАНИЕ: файл содержит приватные ключи — храни в защищённом месте.", "Full server state backup: WireGuard key, server.env, all clients and keys, tokens, panel settings (labels, assignments, access, subscriber token). Excludes binaries/packages. Restore on a clean VPS: run the turnkey install first, then upload the backup here — the server key returns and clients reconnect without recreation. WARNING: the file contains private keys — store it securely.")}</h2>
    <p style="font-size:.85em;color:var(--muted);margin:4px 0 8px">⚠ {tr("Файл содержит приватные ключи. Храни в защищённом месте.","File contains private keys. Store it securely.")}</p>
    <a href="/api/backup/download" class="btn btn-primary btn-sm" style="background:#16a34a">⬇ {tr("Скачать бэкап","Download backup")}</a>
    <form method="post" action="/api/backup/restore" enctype="multipart/form-data" style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <input type="file" name="backup" accept=".gz,.tar.gz" required style="font-size:.85em">
      <button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('{tr("Восстановить из бэкапа? Текущее состояние будет перезаписано (создаётся снимок до восстановления).","Restore from backup? Current state will be overwritten (a pre-restore snapshot is saved).")}')">{tr("Загрузить и восстановить","Upload & restore")}</button>
    </form>
    </div>

    <div class="card">
    <h2>{tr("Обфускация (маскировка)","Obfuscation (masking)")} {hlp("Параметры wg-obfuscator. masking: AUTO (адаптивно), STUN (под STUN-трафик), NONE (без маскировки). max-dummy — добавочные мусорные байты. idle — таймаут простоя (сек). Сохранение отправляет параметры на ВСЕ роутеры по pull-каналу — применяются за ~15 сек без перевыдачи конфига. Серверный обфускатор остаётся AUTO и принимает любой клиентский режим.", "wg-obfuscator params. masking: AUTO (adaptive), STUN (mimic STUN), NONE (no masking). max-dummy — extra junk bytes. idle — idle timeout (s). Saving pushes the params to ALL routers over the pull channel — applied in ~15s without re-issuing configs. The server obfuscator stays AUTO and accepts any client mode.")}</h2>
    <form method="post" class="form-row" style="flex-wrap:wrap;gap:10px;align-items:center">
      <input type="hidden" name="action" value="save_obf">
      <label>masking
        <select name="obf_masking" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px;border-radius:6px">
          {"".join(f'<option value="{m}"{" selected" if (s.get("obf_params",{}).get("masking","AUTO")==m) else ""}>{m}</option>' for m in ("AUTO","STUN","NONE"))}
        </select></label>
      <label>max-dummy <input type="number" name="obf_max_dummy" value="{s.get('obf_params',{}).get('max_dummy','4')}" min="0" max="255" style="width:70px;padding:5px"></label>
      <label>idle (s) <input type="number" name="obf_idle" value="{s.get('obf_params',{}).get('idle','300')}" min="10" max="3600" style="width:80px;padding:5px"></label>
      <button class="btn btn-primary btn-sm" type="submit">{tr("Сохранить и отправить","Save & push")}</button>
    </form>
    </div>

    <div class="card">
    <h2>{tr("Информация о сервере","Server info")}</h2>
    <table>
    <tr><td>VPS IP</td><td>{SERVER_IP}</td></tr>
    <tr><td>{tr("WireGuard порт","WireGuard port")}</td><td>51820 (localhost)</td></tr>
    <tr><td>{tr("Порты обфускатора","Obfuscator ports")}</td><td>{_load_server_env().get('OBFUSCATOR_PORTS', '2083,5443,993')}</td></tr>
    <tr><td>{tr("Адрес панели","Panel URL")}</td><td>{panel_base_url()}</td></tr>
    <tr><td>{tr("Порт панели","Panel port")}</td><td>{panel_port()}</td></tr>
    <tr><td>{tr("Протокол панели","Panel protocol")}</td><td>{panel_scheme().upper()}</td></tr>
    <tr><td>{tr("Клиенты Phobos","Phobos clients")}</td><td>{CLIENTS_DIR}</td></tr>
    </table>
    </div>

    <div class="card">
    <h2>WARP / WARP+ {hlp("Этот блок нужен для двух разных задач. Первая: отправить весь исходящий трафик клиентов Phobos через Cloudflare WARP. Вторая: открыть на сервере отдельные UDP relay-порты и перекинуть их на endpoint WARP/WARP+. Ниже можно выбрать режим, источник профиля и при желании вставить WARP+ key или полный custom WireGuard профиль.", "This block handles two different jobs. First: send all Phobos client egress through Cloudflare WARP. Second: open dedicated UDP relay ports on this server and forward them to WARP/WARP+ endpoint. Below you can choose mode, profile source, and optionally paste WARP+ key or full custom WireGuard profile.")}</h2>
    <p style="font-size:.9em;color:var(--text);margin:6px 0 12px 0">{tr("Как это работает: выбираешь режим, заполняешь только нужные поля, жмёшь «Сохранить WARP настройки», потом «Enable selected mode». В каждый момент активен один режим: либо egress, либо relay. Кнопка Disable выключает текущий режим и убирает его правила.", "How it works: choose mode, fill only fields you need, press 'Save WARP settings', then 'Enable selected mode'. Only one mode is active at a time: either egress or relay. Disable turns current mode off and removes its rules.")}</p>
    <table>
    <tr><td>{tr("Статус","Status")}</td><td><b style="color:{'#22c55e' if warp.get('enabled') else '#f59e0b'}">{warp_state}</b> ({_html_attr(warp_service)})</td></tr>
    <tr><td>{tr("Режим","Mode")}</td><td>{warp_mode} {hlp("egress включает интерфейс warp и меняет исходящий маршрут для подсети клиентов Phobos. relay не меняет интернет-выход клиентов, а только открывает UDP relay-порты на этом сервере.", "egress brings up warp interface and changes egress route for Phobos client subnet. relay does not change client internet egress; it only opens UDP relay ports on this server.")}</td></tr>
    <tr><td>{tr("Источник профиля","Profile source")}</td><td>{warp_profile_source} {hlp("free — профиль собирается через wgcf. Если сохранён WARP+ key, он применяется к wgcf-аккаунту. custom — используется твой готовый WireGuard профиль, который вставлен ниже.", "free — profile is built through wgcf. If WARP+ key is saved, it is applied to wgcf account. custom — uses your ready WireGuard profile pasted below.")}</td></tr>
    <tr><td>{tr("Подсеть клиентов","Client subnet")}</td><td>{warp_subnet}</td></tr>
    <tr><td>Endpoint</td><td>{warp_endpoint or '—'}</td></tr>
    <tr><td>{tr("Relay ports","Relay ports")}</td><td>{warp_relay_ports or '—'}</td></tr>
    <tr><td>{tr("Relay target","Relay target")}</td><td>{warp_relay_target or '—'}</td></tr>
    <tr><td>{tr("Что именно включается","What gets enabled")}</td><td>{tr("Только выбранный режим. Одновременно egress и relay не держатся.", "Only selected mode. egress and relay are not kept active together.")} {hlp("Если сейчас активен egress и ты включаешь relay, старый egress будет выключен и заменён relay. И наоборот.", "If egress is active and you enable relay, old egress is turned off and replaced by relay. Same in reverse.")}</td></tr>
    <tr><td>{tr("По отдельным клиентам","Per-client control")}</td><td>{tr("Да, через кнопки WARP ON/OFF в списке клиентов.", "Yes, via WARP ON/OFF buttons in client list.")} ({warp_client_count}) {hlp("В режиме egress WARP можно включать точечно по клиентам. Панель запоминает выбор и применяет правила по tunnel IP клиента. В relay режиме эти кнопки не работают.", "In egress mode WARP can be enabled per client. Panel remembers the choice and applies rules by client tunnel IP. These buttons do not work in relay mode.")}</td></tr>
    <tr><td>{tr("WARP+ key","WARP+ key")}</td><td>{tr("сохранён","saved") if warp_license_saved else tr("не задан","not set")}</td></tr>
    <tr><td>{tr("Custom profile","Custom profile")}</td><td>{tr("сохранён","saved") if custom_profile_saved else tr("не задан","not set")}</td></tr>
    <tr><td>{tr("Egress IPv4","Egress IPv4")}</td><td>{warp_egress or '—'}</td></tr>
    </table>
    <form method="post" style="margin-top:10px">
      <input type="hidden" name="action" value="warp_save">
      <div class="form-row"><label>{tr("Режим WARP","WARP mode")}</label>
        <select name="warp_mode" style="max-width:260px">
          <option value="egress" {'selected' if warp_cfg.get('mode') == 'egress' else ''}>egress</option>
          <option value="relay" {'selected' if warp_cfg.get('mode') == 'relay' else ''}>relay</option>
        </select>
        {hlp("Выбирай egress, если хочешь, чтобы интернет-выход клиентов Phobos шёл через WARP. Выбирай relay, если нужен отдельный UDP relay-порт на этом сервере, который перекидывает трафик на WARP/WARP+ endpoint. Важно: relay не предназначен для обычного Phobos-клиента как замена его home.conf. Для relay нужен отдельный WARP/WireGuard клиентский профиль, который смотрит в этот relay-порт.", "Choose egress when you want Phobos client internet egress to go through WARP. Choose relay when you need dedicated UDP relay port on this server that forwards traffic to WARP/WARP+ endpoint. Important: relay is not meant to replace regular Phobos client home.conf. Relay expects separate WARP/WireGuard client profile pointed at this relay port.")}
      </div>
      <div class="form-row"><label>{tr("Источник профиля","Profile source")}</label>
        <select name="warp_profile_source" style="max-width:260px">
          <option value="free" {'selected' if warp_cfg.get('profile_source') == 'free' else ''}>free WARP (wgcf)</option>
          <option value="custom" {'selected' if warp_cfg.get('profile_source') == 'custom' else ''}>custom / WARP+</option>
        </select>
        {hlp("Если у тебя нет своего профиля, обычно начинай с free. Если есть WARP+ key, просто вставь его ниже: free-режим сам попробует собрать WARP+ профиль через wgcf. Если у тебя уже есть готовый WireGuard профиль WARP/WARP+, выбирай custom и вставляй его в поле ниже.", "If you do not have your own profile, usually start with free. If you have WARP+ key, just paste it below: free mode will try to build WARP+ profile through wgcf. If you already have ready WARP/WARP+ WireGuard profile, choose custom and paste it in field below.")}
      </div>
      <div class="form-row"><label>{tr("WARP+ key","WARP+ key")}</label><input type="text" name="warp_license_key" value="{_html_attr(warp_cfg.get('license_key', '') or warp_license_key)}" placeholder="ABCD-1234-...">{hlp("Это не полный профиль, а только license key от WARP+. Нужен для сценария: source=free, но аккаунт должен стать WARP+. Порядок такой: вставил key, сохранил настройки, потом включил режим. Если key неверный, включение не пройдёт.", "This is not full profile, only WARP+ license key. Use it for source=free but upgraded WARP+ account. Flow: paste key, save settings, then enable mode. If key is wrong, enable will fail.")}</div>
      <div class="form-row"><label>{tr("Очистить WARP+ key","Clear WARP+ key")}</label><input type="checkbox" name="warp_clear_license" value="1" style="width:auto">{hlp("Отметь и нажми Save WARP settings, чтобы удалить сохранённый WARP+ key.", "Check and press Save WARP settings to remove the saved WARP+ key.")}</div>
      <div class="form-row"><label>{tr("Relay ports","Relay ports")}</label><input type="text" name="warp_relay_ports" value="{_html_attr(warp_cfg.get('relay_ports', '4500'))}" placeholder="4500 or 4500,4501,4502">{hlp("Нужно только для relay mode. Здесь задаются UDP-порты именно на этом сервере. Клиент или роутер будет подключаться к IP этого сервера и к одному из этих портов, а сервер уже перекинет трафик дальше на endpoint WARP/WARP+.", "Used only for relay mode. These are UDP ports on this server itself. Client or router connects to this server IP and one of these ports, then server forwards traffic to WARP/WARP+ endpoint.")}</div>
      <div class="form-row"><label>{tr("Relay target override","Relay target override")}</label><input type="text" name="warp_relay_target" value="{_html_attr(warp_cfg.get('relay_target', ''))}" placeholder="engage.cloudflareclient.com:2408">{hlp("Обычно поле можно не трогать. Если оставить пустым, relay возьмёт Endpoint из выбранного профиля. Заполняй только если хочешь вручную указать другой host:port.", "Usually you can leave this alone. If empty, relay uses Endpoint from selected profile. Fill only if you want to force another host:port manually.")}</div>
      <div class="form-row"><label>{tr("Custom profile","Custom profile")}</label><textarea name="warp_custom_profile" rows="12" style="width:min(100%,620px);min-height:230px;line-height:1.4;resize:vertical;font-family:Menlo,Monaco,Consolas,monospace;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)" placeholder="[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\nPersistentKeepalive = 25">{_html_attr(custom_warp_profile)}</textarea>{hlp("Сюда вставляется полный WireGuard профиль WARP/WARP+. Это отдельный путь, если не хочешь использовать wgcf и WARP+ key. Такой профиль можно потом использовать и для egress, и для relay.", "Paste full WARP/WARP+ WireGuard profile here. This is separate path if you do not want to use wgcf and WARP+ key. Same profile can then be used for both egress and relay.")}</div>
      <div class="form-row"><label>{tr("Очистить custom profile","Clear custom profile")}</label><input type="checkbox" name="warp_clear_custom" value="1" style="width:auto">{hlp("Отметь и нажми Save WARP settings, чтобы удалить сохранённый WARP+/custom профиль.", "Check and press Save WARP settings to remove saved WARP+/custom profile.")}</div>
      <div class="form-row"><label></label><button class="btn btn-sm" style="background:#475569" type="submit">{tr("Сохранить WARP настройки","Save WARP settings")}</button></div>
    </form>
    <p style="font-size:.85em;color:var(--muted);margin:8px 0">{tr("Коротко: egress поднимает WARP на сервере, а дальше ты сам включаешь WARP точечно по клиентам кнопками WARP ON/OFF в разделе клиентов. relay нужен, когда нужен отдельный UDP вход на этом сервере с переадресацией в WARP/WARP+. Relay — это сценарий для отдельного WARP/WireGuard профиля, а не для штатного Phobos home.conf.", "Short version: egress brings WARP up on server, then you enable it per client with WARP ON/OFF buttons in client list. relay is for dedicated UDP entrypoint on this server forwarded into WARP/WARP+. Relay is for separate WARP/WireGuard profile, not for standard Phobos home.conf.")}</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <form method="post" style="display:inline">
        <input type="hidden" name="action" value="warp_enable">
        <input type="hidden" name="warp_mode" value="{_html_attr(warp_cfg.get('mode', 'egress'))}">
        <input type="hidden" name="warp_profile_source" value="{_html_attr(warp_cfg.get('profile_source', 'free'))}">
        <input type="hidden" name="warp_relay_ports" value="{_html_attr(warp_cfg.get('relay_ports', '4500'))}">
        <input type="hidden" name="warp_relay_target" value="{_html_attr(warp_cfg.get('relay_target', ''))}">
        <button class="btn btn-primary" type="submit" onclick="return confirm('{tr("Включить выбранный режим WARP?","Enable selected WARP mode?")}')">{tr("Enable selected mode","Enable selected mode")}</button>
      </form>
      <form method="post" style="display:inline"><input type="hidden" name="action" value="warp_disable"><button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('{tr("Выключить WARP/relay и убрать правила?","Disable WARP/relay and remove rules?")}')">Disable</button></form>
      <form method="post" style="display:inline"><input type="hidden" name="action" value="warp_status"><button class="btn btn-sm" style="background:#334155" type="submit">{tr("Обновить статус","Refresh status")}</button></form>
    </div>
    {f'<p style="color:var(--err);font-size:.85em;margin-top:8px">{warp_error}</p>' if warp_error else ''}
    </div>

    <div class="card">
    <h2>{tr("Установка на роутер","Router install")}</h2>
    <p style="color:var(--muted);font-size:.85em;margin-bottom:8px">{tr("Keenetic/Netcraze с Entware — выполнить по SSH на роутере:","Keenetic/Netcraze with Entware — run over SSH on the router:")}</p>
    {_render_install_commands()}
    </div>
    </div>"""
    return render(html)


TOKENS_FILE = f"{PHOBOS_DIR}/tokens/tokens.json"


def _render_install_commands():
    """Read tokens and render install commands for each client."""
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE) as f:
                tokens = json.load(f)
        else:
            tokens = []
    except Exception:
        tokens = []

    if not tokens:
        return '<p style="color:var(--muted);font-size:.85em">Нет активных токенов. Добавьте клиента.</p>'

    port = panel_port()
    lines = ""
    for t in tokens:
        client = t.get("client", "?")
        token = t.get("token", "")
        expires = t.get("expires", 0)
        exp_str = datetime.fromtimestamp(expires).strftime("%Y-%m-%d %H:%M") if expires else "?"
        cmd = install_command(token, port)
        lines += f"""
        <div style="margin-bottom:10px">
        <span style="color:var(--accent);font-size:.85em">{client}</span>
        <span style="color:var(--muted);font-size:.75em"> (до {exp_str})</span>
        <div style="display:flex;gap:8px;align-items:flex-start;margin-top:4px">
        <code style="background:var(--bg);padding:8px 12px;border-radius:6px;display:block;font-size:.82em;white-space:nowrap;overflow-x:auto;flex:1">{cmd}</code>
        <button class="btn btn-sm" style="background:#475569;white-space:nowrap" type="button" onclick="var x=document.createElement('textarea');x.value=this.previousElementSibling.textContent;document.body.appendChild(x);x.select();document.execCommand('copy');document.body.removeChild(x);this.textContent='✓'">📋 {tr("Копировать","Copy")}</button>
        </div>
        </div>"""
    uninstall_cmd = "/opt/etc/Phobos/phobos-uninstall.sh"
    lines += f"""
        <div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--border)">
        <span style="color:var(--accent);font-size:.85em">{tr("Удалить с роутера", "Remove from router")}</span>
        <span style="color:var(--muted);font-size:.75em"> ({tr("общая команда для всех клиентов", "same command for all clients")})</span>
        <div style="display:flex;gap:8px;align-items:flex-start;margin-top:4px">
        <code style="background:var(--bg);padding:8px 12px;border-radius:6px;display:block;font-size:.82em;white-space:nowrap;overflow-x:auto;flex:1">{uninstall_cmd}</code>
        <button class="btn btn-sm" style="background:#475569;white-space:nowrap" type="button" onclick="var x=document.createElement('textarea');x.value=this.previousElementSibling.textContent;document.body.appendChild(x);x.select();document.execCommand('copy');document.body.removeChild(x);this.textContent='✓'">📋 {tr("Копировать","Copy")}</button>
        </div>
        </div>"""
    return lines


SERVERS_FILE = f"{PANEL_DIR}/servers.json"


def load_servers():
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE) as f:
            return json.load(f)
    return []


def save_servers(servers):
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)


def panel_port():
    try:
        return open(os.path.join(PANEL_DIR, ".port")).read().strip() or "8443"
    except Exception:
        return "8443"


def panel_scheme():
    scheme = (os.environ.get("PANEL_SCHEME") or "").strip().lower()
    if scheme in ("http", "https"):
        return scheme
    try:
        scheme = open(os.path.join(PANEL_DIR, ".scheme")).read().strip().lower()
        if scheme in ("http", "https"):
            return scheme
    except Exception:
        pass
    return "http"


def panel_base_url(host=None):
    return f"{panel_scheme()}://{host or SERVER_IP}:{panel_port()}"


def _server_api_key_candidates(server):
    keys = []
    for key in (server.get("api_key", ""), load_settings().get("server_api_key", "")):
        if key and key not in keys:
            keys.append(key)
    return keys


def _remember_server_api_key(ip, api_key):
    if not ip or not api_key:
        return
    servers = load_servers()
    changed = False
    for srv in servers:
        if srv.get("ip") == ip and srv.get("api_key") != api_key:
            srv["api_key"] = api_key
            changed = True
    if changed:
        save_servers(servers)


def secondary_api_request(server, path, data=None, timeout=10):
    import urllib.error
    import urllib.request
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode() if data is not None else None
    last_error = None
    for key in _server_api_key_candidates(server):
        headers["X-API-Key"] = key
        try:
            req = urllib.request.Request(
                f"http://{server['ip']}:8444{path}",
                data=body,
                headers=headers,
                method="POST" if body is not None else "GET",
            )
            resp = urllib.request.urlopen(req, timeout=timeout)
            _remember_server_api_key(server.get("ip", ""), key)
            server["api_key"] = key
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code in (401, 403):
                continue
            raise
    if last_error:
        raise last_error
    raise RuntimeError("no API key for secondary server")


def install_command(token, port=None):
    port = port or panel_port()
    primary = f"{panel_scheme()}://{SERVER_IP}:{port}/init/{token}.sh"
    urls = [primary, f"http://{SERVER_IP}/init/{token}.sh"]
    return ("p=/tmp/phobos-init-$$.sh; ok=0; "
            f"for u in {' '.join(urls)}; do "
            "rm -f $p; "
            "(wget -q -O $p $u || wget --no-check-certificate -q -O $p $u || curl -kfsSL -o $p $u || curl -fsSL -o $p $u) 2>/dev/null || continue; "
            "head -c 2 $p | grep -q \"#!\" || continue; "
            "sh $p && ok=1 && break; "
            "done; rm -f $p; [ $ok -eq 1 ] || echo ERROR_install_script_download_failed")


@app.route("/init/<path:name>")
def serve_init(name):
    return send_from_directory(f"{PHOBOS_DIR}/www/init", name, mimetype="application/x-sh")


@app.route("/packages/<path:name>")
def serve_package(name):
    return send_from_directory(f"{PHOBOS_DIR}/www/packages", name, mimetype="application/octet-stream")


_SPEED_CHUNK = os.urandom(1 << 20)
_speed_busy = set()


@app.route("/speedtest")
def speedtest_page():
    """Public: a VPN client opens http://10.25.0.1:<port>/speedtest on its device
    to measure real device <-> server speed through the tunnel."""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phobos speed test</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;padding:24px 16px;text-align:center}}
@media(prefers-color-scheme:dark){{body{{background:#0f172a;color:#e2e8f0}}}}
.v{{font-size:2.4em;font-weight:700;margin:6px 0}}.l{{color:#64748b}}button{{font-size:1.1em;padding:12px 28px;border:0;border-radius:10px;background:#4f46e5;color:#fff;margin-top:18px}}
.row{{display:flex;gap:28px;justify-content:center;flex-wrap:wrap;margin-top:18px}}</style></head><body>
<h2>🛡️ Phobos — {tr("скорость до сервера", "speed to server")}</h2>
<div class="row"><div><div class="l">ping</div><div class="v" id="p">—</div></div>
<div><div class="l">↓ {tr("Мбит/с", "Mbit/s")}</div><div class="v" id="d">—</div></div>
<div><div class="l">↑ {tr("Мбит/с", "Mbit/s")}</div><div class="v" id="u">—</div></div></div>
<button id="b" onclick="run()">{tr("Начать", "Start")}</button>
<p class="l" style="font-size:.85em;margin-top:22px">{tr("Открой эту страницу на устройстве с включённым VPN по адресу туннеля — так замеряется реальный канал до сервера.", "Open this page on a device with VPN on, via the tunnel address — this measures the real path to the server.")}</p>
<script>
async function run(){{const b=document.getElementById('b');b.disabled=true;b.textContent='…';
let t=performance.now();await fetch('speedtest/down?mb=0',{{cache:'no-store'}});document.getElementById('p').textContent=Math.round(performance.now()-t)+' ms';
t=performance.now();let r=await fetch('speedtest/down?mb=40',{{cache:'no-store'}});let n=(await r.arrayBuffer()).byteLength;
document.getElementById('d').textContent=(n*8/((performance.now()-t)/1000)/1e6).toFixed(1);
const body=new Uint8Array(20<<20);crypto.getRandomValues(body.subarray(0,65536));
t=performance.now();await fetch('speedtest/up',{{method:'POST',body:body}});
document.getElementById('u').textContent=(body.length*8/((performance.now()-t)/1000)/1e6).toFixed(1);
b.disabled=false;b.textContent='{tr("Ещё раз", "Again")}';}}
</script></body></html>"""


@app.route("/speedtest/down")
def speedtest_down():
    try:
        mb = max(0, min(100, int(request.args.get("mb", "10"))))
    except ValueError:
        mb = 10
    ip = request.remote_addr or "?"
    if mb and ip in _speed_busy:
        return ("busy", 429)

    def gen():
        _speed_busy.add(ip)
        try:
            for _ in range(mb):
                yield _SPEED_CHUNK
        finally:
            _speed_busy.discard(ip)
    return app.response_class(gen(), mimetype="application/octet-stream",
                              headers={"Cache-Control": "no-store", "Content-Length": str(mb << 20)})


@app.route("/speedtest/up", methods=["POST"])
def speedtest_up():
    n = 0
    stream = request.stream
    while n < (100 << 20):
        chunk = stream.read(1 << 16)
        if not chunk:
            break
        n += len(chunk)
    return {"bytes": n}


@app.route("/server/<path:name>")
def serve_server_bootstrap(name):
    # Public bootstrap files only. No secrets live in these scripts.
    if name not in ("secondary-setup.sh", "api.py", "update.sh", "phobos-limit.sh", "phobos-speedtest.sh",
                    "phobos-cascade.sh"):
        return ("not found", 404)
    mimetype = "application/x-sh" if name.endswith(".sh") else "text/plain"
    return send_from_directory(f"{PHOBOS_DIR}/server", name, mimetype=mimetype)


def get_main_server_info():
    env = _load_server_env()
    return {
        "ip": SERVER_IP,
        "ports": env.get("OBFUSCATOR_PORTS", "2083,5443,993"),
        "obfuscator_key": env.get("OBFUSCATOR_KEY", ""),
        "is_primary": True
    }


def get_all_servers_ordered():
    s = load_settings()
    servers = load_servers()
    main_info = get_main_server_info()
    order = s.get("server_order", [])

    by_ip = {}
    by_ip[main_info["ip"]] = {"ip": main_info["ip"], "ports": main_info["ports"],
                               "obfuscator_key": main_info["obfuscator_key"], "is_primary": True}
    for srv in servers:
        by_ip[srv["ip"]] = {**srv, "is_primary": False}

    if not order or main_info["ip"] not in order:
        order = [main_info["ip"]] + [sv["ip"] for sv in servers]

    result = []
    for ip in order:
        if ip in by_ip:
            result.append(by_ip[ip])
    for ip, sv in by_ip.items():
        if ip not in order:
            result.append(sv)
    return result


def check_server_health(server):
    """Check secondary server health via API."""
    try:
        return secondary_api_request(server, "/api/health", timeout=5)
    except Exception as e:
        return {"status": "error", "error": str(e)}


def sync_peer_to_server(server, public_key, allowed_ips, action="add"):
    """Add or remove peer on secondary server."""
    try:
        return secondary_api_request(server, f"/api/peers/{action}", {
            "public_key": public_key, "allowed_ips": allowed_ips
        }, timeout=10)
    except Exception as e:
        return {"status": "error", "msg": str(e)[:200]}


def sync_peer_to_all_servers(public_key, allowed_ips, action="add"):
    """Sync peer to all secondary servers."""
    servers = load_servers()
    for srv in servers:
        if srv.get("enabled", True):
            sync_peer_to_server(srv, public_key, allowed_ips, action)


def sync_missing_peers_to_secondaries(server=None):
    """Best-effort peer repair: every secondary must already know every client.
    Router failover can only work if the target server has the client's WG peer.
    """
    servers = [server] if server else [srv for srv in load_servers() if srv.get("enabled", True)]
    clients = get_clients()
    synced = 0
    for srv in servers:
        health = check_server_health(srv)
        if health.get("status") not in ("ok", None):
            continue
        remote_keys = set(health.get("peer_keys", []) or [])
        for c in clients:
            pub = c.get("public_key", "")
            tip = (c.get("tunnel_ip_v4") or "").split("/")[0]
            if not pub or not tip or pub in remote_keys:
                continue
            res = sync_peer_to_server(srv, pub, f"{tip}/32", "add")
            if res.get("status") == "ok":
                synced += 1
                remote_keys.add(pub)
    return synced


@app.route("/download/apk")
@auth_required
def download_apk():
    """PhobosWG APK: local copy if the server has one, else the release on Gitea."""
    local = "/opt/Phobos/www/app/PhobosWG.apk"
    if os.path.exists(local):
        from flask import send_file
        return send_file(local, as_attachment=True, download_name="PhobosWG.apk",
                         mimetype="application/vnd.android.package-archive")
    return redirect(f"{PCA_GIT}/releases/download/{APK_TAG}/PhobosWG.apk")


@app.route("/client/<cid>/conf/<mode>")
@auth_required
def client_conf_download(cid, mode):
    m = "ios" if mode == "ios" else "android"
    if m == "android":
        return ("Android/PhobosWG uses phobos:// QR/link import; .conf import is only valid for iOS/plain WireGuard.", 400)
    conf, _link = build_phone_config(cid, m)
    if conf is None:
        return ("client not found", 404)
    if m == "android":
        conf = _pad_conf_with_none(conf)
    return (conf, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="%s-%s.conf"' % (cid, m),
    })


@app.route("/client/<cid>/phone/<mode>")
@auth_required
def client_phone(cid, mode):
    if mode not in ("android", "ios"):
        mode = "android"
    conf, link = build_phone_config(cid, mode)
    if conf is None:
        return ("client not found", 404)
    qr = qr_datauri(link if (mode == "android" and link) else conf)
    if mode == "android":
        title = tr("Android — PhobosWG (с обфускацией)", "Android — PhobosWG (obfuscated)")
        apk_btn = ""
        _apk_local = "/opt/Phobos/www/app/PhobosWG.apk"
        if os.path.exists(_apk_local):
            apk_btn = (f'<p style="margin-top:6px"><a href="http://{SERVER_IP}/app/PhobosWG.apk" '
                       f'class="btn btn-primary" style="background:#16a34a">📥 {tr("Скачать приложение PhobosWG (APK)","Download PhobosWG app (APK)")}</a></p>')
        else:
            _gh_token = ""
            try:
                _gh_token = open("/opt/phobos-panel/.gh_token").read().strip()
            except Exception:
                pass
            if _gh_token:
                apk_btn = (f'<p style="margin-top:6px"><a href="/download/apk" class="btn btn-primary" '
                           f'style="background:#16a34a">📥 {tr("Скачать PhobosWG (APK)","Download PhobosWG (APK)")}</a>'
                           f'<span style="font-size:.8em;color:var(--muted);margin-left:8px">{tr("с GitHub","from GitHub")}</span></p>')
            else:
                apk_btn = (f'<p style="margin-top:6px"><a href="/download/apk" class="btn btn-primary" '
                           f'style="background:#16a34a">📥 {tr("Скачать PhobosWG (APK)","Download PhobosWG (APK)")}</a></p>')
        client_btn = (f'<p style="margin-top:6px"><a href="{PCA_GIT}/releases/download/{APK_TAG}/PCA-Phobos-VPN.apk" '
                      f'class="btn btn-primary" target="_blank" rel="noopener">🛡 {tr("PCA Phobos VPN — наше приложение (раздельный трафик)","PCA Phobos VPN — our app (split tunnelling)")}</a></p>'
                      f'<p style="font-size:.8em;color:var(--muted)">{tr("Поставь любое из двух приложений и открой ссылку ниже на телефоне — профиль импортируется сам.","Install either app and open the link below on the phone — the profile imports itself.")}</p>')
        extra = (client_btn + apk_btn +
                 f'<p>{tr("phobos:// ссылка — импорт в PCA Phobos VPN или PhobosWG:", "phobos:// link — import into PCA Phobos VPN or PhobosWG:")} <a href="{link}">{tr("открыть", "open")}</a></p>'
                 f'<textarea readonly onclick="this.select()" style="width:100%;height:90px;font-size:.75em">{link}</textarea>')
    else:
        title = tr("iPhone / iOS WireGuard (без обфускации)", "iPhone / iOS WireGuard (plain, no obfuscation)")
        extra = (f'<p><a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener" class="btn btn-primary" style="background:#0ea5e9">📥 {tr("WireGuard в App Store","WireGuard on the App Store")}</a> <a href="/client/{cid}/conf/ios" class="btn" style="background:#7c3aed">⬇ {tr("Скачать .conf","Download .conf")}</a></p>'
                 f'<p style="color:var(--warn)">{tr("⚠ Обычный WireGuard без маскировки (Endpoint → :51820). На сервере должен быть открыт порт 51820 (ALLOW_PLAIN_WG=1).", "⚠ Plain WireGuard, no obfuscation (Endpoint → :51820). Port 51820 must be open on the server (ALLOW_PLAIN_WG=1).")}</p>')
    html = f"""
    <div class="container">
    {nav('clients')}
    <div class="card" style="text-align:center">
    <h2>{cid} — {title}</h2>
    <img src="{qr}" alt="QR" style="max-width:340px;width:100%;background:#fff;padding:10px;border-radius:10px;image-rendering:pixelated"><br>
    <p style="margin-top:10px">{tr("Отсканируй QR в приложении или импортируй конфиг:", "Scan the QR in the app or import the config:")}</p>
    {extra}
    <textarea readonly onclick="this.select()" style="width:100%;height:250px;font-family:monospace;font-size:.78em">{conf}</textarea>
    <p style="margin-top:10px"><a href="/clients" class="btn btn-sm">{tr("← назад", "← back")}</a></p>
    </div></div>"""
    return render(html)


@app.route("/api/router-config/<client_id>")
def router_config(client_id):
    """NAT-friendly config pull: router fetches its own failover.conf.
    Auth via per-client pull_token (falls back to server_api_key)."""
    st = load_settings()
    token = request.args.get("token", "")
    acc = st.get("router_access", {}).get(client_id, {})
    expected = acc.get("pull_token", "") or st.get("server_api_key", "")
    if not expected or token != expected:
        return ("forbidden", 403)
    conf = generate_failover_conf_for_client(client_id)
    return (conf, 200, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/client/<cid>/router-config")
@auth_required
def client_router_config(cid):
    if not any(c.get("client_id") == cid for c in get_clients()):
        return ("client not found", 404)
    token = _latest_token_for_client(cid)
    cmd = install_command(token) if token else ""
    title = tr("Установка на роутер", "Router install")
    copy = tr("Копировать", "Copy")
    copied = tr("Скопировано", "Copied")
    body = (f"""
    <p style="color:var(--muted);font-size:.85em">{tr("Одна команда для вставки в SSH роутера.", "One command to paste into router SSH.")}</p>
    <div style="display:flex;gap:8px;align-items:flex-start">
    <code id="routerCmd" style="background:var(--bg);padding:8px 12px;border-radius:6px;display:block;font-size:.82em;white-space:nowrap;overflow-x:auto;flex:1">{cmd}</code>
    <button class="btn btn-primary btn-sm" type="button" onclick="var x=document.createElement('textarea');x.value=document.getElementById('routerCmd').textContent;document.body.appendChild(x);x.select();document.execCommand('copy');document.body.removeChild(x);this.textContent='{copied}'">📋 {copy}</button>
    </div>
    """ if cmd else f'<p style="color:var(--err)">{tr("Нет активной команды установки. Создай/обнови клиента, чтобы выпустить install token.", "No active install command. Create/update the client to issue an install token.")}</p>')
    html = f"""
    <div class="container">
    {nav('clients')}
    <div class="card">
    <h2>{cid} — {title}</h2>
    {body}
    <p style="margin-top:10px"><a href="/clients" class="btn btn-sm">{tr("← назад", "← back")}</a></p>
    </div></div>"""
    return render(html)


# ── Keenetic RCI console (KeenDNS, ndm-challenge auth) ──────────────────────
# Keenetic routers behind NAT don't accept SSH (neither WAN nor WG tunnel).
# Control them via RCI over KeenDNS HTTPS: ndmc CLI commands -> POST /rci/.
# Auth: sha256(challenge + md5(login:realm:password)) (ndm challenge).
def _rci_base(cid):
    acc = load_settings().get("router_access", {}).get(cid, {})
    url = (acc.get("web_url") or "").strip()
    if not url:
        return None, None, None
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/"), (acc.get("web_login") or "admin"), (acc.get("web_pass") or "")


def _rci_run(cid, command):
    """Run a ndmc CLI command on a Keenetic router via RCI/KeenDNS.
    Returns (ok, text)."""
    import urllib.request, urllib.error, ssl, json as _json, http.cookiejar, hashlib
    base, login, pwd = _rci_base(cid)
    if not base:
        return False, "Не задан web-адрес роутера (Настройки → Доступ к роутерам → KeenDNS URL)."
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                     urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(base + "/auth", timeout=12)  # already authed (cookie) or 200
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return False, f"auth error: HTTP {e.code}"
        realm = e.headers.get("X-NDM-Realm", ""); ch = e.headers.get("X-NDM-Challenge", "")
        if not realm or not ch:
            return False, "auth: no challenge headers"
        md5 = hashlib.md5(f"{login}:{realm}:{pwd}".encode()).hexdigest()
        sha = hashlib.sha256(f"{ch}{md5}".encode()).hexdigest()
        body = _json.dumps({"login": login, "password": sha}).encode()
        req = urllib.request.Request(base + "/auth", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            op.open(req, timeout=12)
        except Exception as ex:
            return False, f"auth failed (проверь логин/пароль web-панели роутера): {ex}"
    except Exception as e:
        return False, f"connect failed: {e}"
    try:
        req = urllib.request.Request(base + "/rci/", data=_json.dumps({"parse": command}).encode(),
                                     headers={"Content-Type": "application/json"})
        r = op.open(req, timeout=25)
        data = _json.loads(r.read())
        return True, _json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return False, f"rci error: {e}"


@app.route("/api/router/<cid>/rci", methods=["POST"])
@auth_required
def api_router_rci(cid):
    command = (request.form.get("command", "") or "").strip()
    if not command:
        return ("no command", 400)
    ok, text = _rci_run(cid, command)
    return (text, 200 if ok else 502, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/rci/router/<cid>")
@auth_required
def rci_console(cid):
    base, _login, _pwd = _rci_base(cid)
    configured = bool(base)
    note = "" if configured else tr(
        "Web-адрес роутера не задан. Настройки → «Доступ к роутерам» → заполни KeenDNS URL + web-логин/пароль.",
        "Router web URL not set. Settings → Router access → fill KeenDNS URL + web login/password.")
    html_page = f"""
    <div class="container">
    {nav('clients')}
    <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0;border:0;padding:0">🛠 RCI {_html_attr(cid)} {hlp("Консоль ndmc-команд Keenetic через KeenDNS (работает за NAT, SSH не нужен). Введи команду CLI (напр. show version, show interface Wireguard3, show ip hotspot) — роутер выполнит и вернёт JSON. Это НЕ интерактивный bash: каждая строка — отдельная команда RCI.", "Keenetic ndmc command console via KeenDNS (works behind NAT, no SSH). Type a CLI command (e.g. show version) — the router runs it and returns JSON. Not an interactive bash: each line is a separate RCI command.")}</h2>
      <a href="/clients" class="btn btn-sm" style="background:#475569">{tr("Назад","Back")}</a>
    </div>
    {f'<div class="alert alert-warn">{note}</div>' if note else ''}
    <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
      <input id="rciCmd" type="text" placeholder="show version" autocomplete="off"
             style="flex:1;min-width:240px;padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font:14px Menlo,monospace">
      <button id="rciRun" class="btn btn-primary" type="button">{tr("Выполнить","Run")}</button>
    </div>
    <div style="margin-bottom:8px;font-size:.8em;color:var(--muted)">{tr("Быстрые","Quick")}:
      <a href="#" class="rci-q">show version</a> ·
      <a href="#" class="rci-q">show interface Wireguard3</a> ·
      <a href="#" class="rci-q">show ip hotspot</a> ·
      <a href="#" class="rci-q">show system</a> ·
      <a href="#" class="rci-q">show running-config</a>
    </div>
    <pre id="rciOut" style="height:60vh;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;color:var(--text);font:13px Menlo,Monaco,Consolas,monospace;white-space:pre-wrap"></pre>
    </div></div>
    <script>
    (function() {{
      var inp=document.getElementById('rciCmd'), out=document.getElementById('rciOut'), btn=document.getElementById('rciRun');
      function run() {{
        var cmd=inp.value.trim(); if(!cmd) return;
        out.textContent += '$ '+cmd+'\\n';
        var fd=new FormData(); fd.append('command', cmd);
        fetch('/api/router/{cid}/rci', {{method:'POST', body:fd}})
          .then(function(r){{return r.text();}})
          .then(function(t){{ out.textContent += t+'\\n\\n'; out.scrollTop=out.scrollHeight; }})
          .catch(function(e){{ out.textContent += 'ERROR: '+e+'\\n\\n'; }});
        inp.value='';
      }}
      btn.addEventListener('click', run);
      inp.addEventListener('keydown', function(e){{ if(e.key==='Enter') run(); }});
      Array.prototype.forEach.call(document.querySelectorAll('.rci-q'), function(a){{
        a.addEventListener('click', function(e){{ e.preventDefault(); inp.value=a.textContent; run(); }});
      }});
      inp.focus();
    }})();
    </script>"""
    return render(html_page)


def _terminal_target(kind, target):
    if kind == "server":
        if target in ("main", SERVER_IP):
            return {
                "title": f"Main server {SERVER_IP}",
                "mode": "local",
                "cmd": ["/bin/bash", "-l"],
                "env": os.environ.copy(),
            }
        srv = next((sv for sv in load_servers() if sv.get("ip") == target), None)
        if not srv:
            raise ValueError("server not found")
        ssh_pass = srv.get("ssh_pass", "")
        if not ssh_pass:
            raise ValueError("server SSH password missing")
        ssh_user = srv.get("ssh_user", "root") or "root"
        ssh_port = str(srv.get("ssh_port", "22") or "22")
        return {
            "title": f"Server {target}",
            "mode": "ssh",
            "hosts": [target],
            "username": ssh_user,
            "password": ssh_pass,
            "port": int(ssh_port),
        }
    if kind == "router":
        clients = get_clients()
        client = next((c for c in clients if c.get("client_id") == target), None)
        if not client:
            raise ValueError("client not found")
        acc = load_settings().get("router_access", {}).get(target, {})
        ssh_pass = acc.get("ssh_pass", "")
        if not ssh_pass:
            raise ValueError("router SSH password missing")
        ssh_user = acc.get("ssh_user", "root") or "root"
        ssh_port = str(acc.get("ssh_port", "22") or "22")
        ssh_ip = acc.get("ssh_ip") or client.get("tunnel_ip_v4", "").split("/")[0]
        ssh_static = acc.get("ssh_static", "")
        hosts = [h for h in (ssh_static, ssh_ip) if h]
        if not hosts:
            raise ValueError("router SSH IP missing")
        return {
            "title": f"Router {target}",
            "mode": "ssh",
            "hosts": hosts,
            "username": ssh_user,
            "password": ssh_pass,
            "port": int(ssh_port),
        }
    raise ValueError("bad terminal target")


@app.route("/terminal/<kind>/<path:target>")
@auth_required
def terminal_page(kind, target):
    try:
        spec = _terminal_target(kind, target)
        error = "" if sock else "flask-sock is not installed; run phobos-update dev to install terminal dependencies"
    except Exception as e:
        spec = {"title": f"{kind} {target}"}
        error = str(e)
    title = _html_attr(spec.get("title", f"{kind} {target}"))
    ws_path = f"/ws/terminal/{kind}/{target}"
    js_error_line = ""
    if error:
        safe_error = _html_attr(error).replace("\\", "\\\\").replace('"', '\\"')
        js_error_line = f'term.writeln("ERROR: {safe_error}"); return;'
    html_page = f"""
    <div class="container">
    {nav('servers' if kind == 'server' else 'clients')}
    <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px">
      <h2 style="margin:0;border:0;padding:0">🖥️ {title}</h2>
      <a href="{'/servers' if kind == 'server' else '/clients'}" class="btn btn-sm" style="background:#475569">{tr("Назад", "Back")}</a>
    </div>
    <link rel="stylesheet" href="/static/xterm.min.css">
    <div id="terminalStatus" style="color:var(--muted);font-size:.85em;margin-bottom:8px">{_html_attr(error) if error else tr("Подключение...", "Connecting...")}</div>
    <div id="terminal" tabindex="0" style="height:70vh;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;font:14px Menlo,Monaco,Consolas,monospace;color:var(--text);outline:none"></div>
    <script src="/static/xterm.min.js"></script>
    <script src="/static/xterm-addon-fit.min.js"></script>
    <script>
    (function() {{
      var status = document.getElementById('terminalStatus');
      var box = document.getElementById('terminal');
      function simpleTerm() {{
        var t = {{}};
        t.cols = 120; t.rows = 32;
        t.write = function(s) {{ box.textContent += s; box.scrollTop = box.scrollHeight; }};
        t.writeln = function(s) {{ t.write(s + '\\r\\n'); }};
        t.focus = function() {{ box.focus(); }};
        t.onData = function(cb) {{
          box.addEventListener('keydown', function(e) {{
            var data = '';
            if (e.key === 'Enter') data = '\\r';
            else if (e.key === 'Backspace') data = '\\x7f';
            else if (e.key === 'Tab') data = '\\t';
            else if (e.key === 'ArrowUp') data = '\\x1b[A';
            else if (e.key === 'ArrowDown') data = '\\x1b[B';
            else if (e.key === 'ArrowRight') data = '\\x1b[C';
            else if (e.key === 'ArrowLeft') data = '\\x1b[D';
            else if (e.ctrlKey && e.key.length === 1) data = String.fromCharCode(e.key.toUpperCase().charCodeAt(0) - 64);
            else if (!e.metaKey && !e.altKey && e.key.length === 1) data = e.key;
            if (data) {{ e.preventDefault(); cb(data); }}
          }});
          window.addEventListener('paste', function(e) {{
            if (document.activeElement !== box) return;
            var text = (e.clipboardData || window.clipboardData).getData('text');
            if (text) {{ e.preventDefault(); cb(text); }}
          }});
        }};
        return t;
      }}
      var term;
      if (window.Terminal) {{
        term = new Terminal({{cursorBlink:true, convertEol:true, scrollback:5000, fontSize:14, fontFamily:'Menlo, Monaco, Consolas, monospace', theme:{{background:'#020617', foreground:'#e2e8f0'}}}});
        box.style.padding = '6px';
        box.style.whiteSpace = 'normal';
        term.open(box);
        if (window.FitAddon) {{
          var fitAddon = new FitAddon.FitAddon();
          term.loadAddon(fitAddon);
          setTimeout(function() {{ fitAddon.fit(); }}, 100);
          window.addEventListener('resize', function() {{ fitAddon.fit(); }});
        }}
      }} else {{
        term = simpleTerm();
        status.textContent = '{tr("Подключение... (fallback terminal)", "Connecting... (fallback terminal)")}';
      }}
      {js_error_line}
      var proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
      var ws = new WebSocket(proto + location.host + '{ws_path}');
      ws.onopen = function() {{ status.textContent = '{tr("Подключено", "Connected")}'; term.focus(); }};
      ws.onmessage = function(ev) {{ term.write(ev.data); }};
      ws.onclose = function() {{ status.textContent = '{tr("Отключено", "Disconnected")}'; term.writeln('\\r\\n[disconnected]'); }};
      ws.onerror = function() {{ status.textContent = '{tr("Ошибка WebSocket", "WebSocket error")}'; }};
      term.onData(function(data) {{ if (ws.readyState === WebSocket.OPEN) ws.send(data); }});
      window.addEventListener('resize', function() {{
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({{type:'resize', cols:term.cols, rows:term.rows}}));
      }});
    }})();
    </script>
    </div></div>"""
    return render(html_page)


def _terminal_ws_loop(ws, kind, target):
    try:
        spec = _terminal_target(kind, target)
    except Exception as e:
        ws.send(f"ERROR: {e}\r\n")
        return
    if spec.get("mode") == "ssh":
        return _terminal_ssh_ws_loop(ws, spec)
    return _terminal_local_ws_loop(ws, spec)


def _terminal_local_ws_loop(ws, spec):
    import pty, select, signal, struct, termios
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(spec["cmd"], stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                            env=spec.get("env") or os.environ.copy(), close_fds=True,
                            preexec_fn=os.setsid)
    os.close(slave_fd)
    stop = threading.Event()

    def set_winsize(cols, rows):
        try:
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", int(rows), int(cols), 0, 0))
        except Exception:
            pass

    def reader():
        try:
            while not stop.is_set():
                r, _, _ = select.select([master_fd], [], [], 0.2)
                if master_fd in r:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    ws.send(data.decode(errors="replace"))
                if proc.poll() is not None:
                    break
        except Exception:
            pass
        finally:
            stop.set()

    threading.Thread(target=reader, daemon=True).start()
    try:
        while not stop.is_set():
            raw = ws.receive(timeout=1)
            if raw is None:
                if proc.poll() is not None:
                    break
                continue
            try:
                msg = json.loads(raw)
            except Exception:
                msg = {"type": "input", "data": raw}
            if msg.get("type") == "resize":
                set_winsize(msg.get("cols", 80), msg.get("rows", 24))
            else:
                os.write(master_fd, str(msg.get("data", raw)).encode())
    finally:
        stop.set()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGHUP)
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass


def _terminal_ssh_ws_loop(ws, spec):
    import asyncio
    try:
        import asyncssh
    except Exception as e:
        ws.send(f"ERROR: asyncssh is not installed: {e}\r\n")
        return

    def format_ssh_error(exc):
        detail = str(exc).strip()
        if detail:
            return detail
        if isinstance(exc, TimeoutError):
            return "Connection timed out"
        return exc.__class__.__name__ or "Connection failed"

    async def run_ssh():
        last_error = None
        for host in spec.get("hosts", []):
            try:
                conn = await asyncssh.connect(
                    host=host,
                    port=spec.get("port", 22),
                    username=spec.get("username", "root"),
                    password=spec.get("password", ""),
                    known_hosts=None,
                    connect_timeout=10,
                )
                ws.send(f"Connected to {host}\r\n")
                break
            except Exception as e:
                last_error = e
                ws.send(f"ssh: connect to host {host} port {spec.get('port', 22)}: {format_ssh_error(e)}\r\n")
        else:
            ws.send(f"\r\nConnection error: {format_ssh_error(last_error)}\r\n")
            return

        async with conn:
            process = await conn.create_process(term_type="xterm-256color", term_size=(120, 40))
            stop = asyncio.Event()

            async def read_output():
                try:
                    while not stop.is_set():
                        data = await process.stdout.read(4096)
                        if not data:
                            break
                        ws.send(data)
                except Exception:
                    pass
                finally:
                    stop.set()

            async def read_input():
                try:
                    while not stop.is_set():
                        raw = await asyncio.to_thread(lambda: ws.receive(timeout=1))
                        if raw is None:
                            continue
                        try:
                            msg = json.loads(raw)
                        except Exception:
                            process.stdin.write(raw)
                            continue
                        if msg.get("type") == "resize":
                            process.change_terminal_size(int(msg.get("cols", 120)), int(msg.get("rows", 40)))
                        else:
                            process.stdin.write(str(msg.get("data", "")))
                except Exception:
                    pass
                finally:
                    stop.set()

            tasks = [asyncio.create_task(read_output()), asyncio.create_task(read_input())]
            await stop.wait()
            for task in tasks:
                task.cancel()
            process.close()

    asyncio.run(run_ssh())


if sock:
    @sock.route("/ws/terminal/<kind>/<path:target>")
    def terminal_ws(ws, kind, target):
        if not session.get("auth"):
            ws.send("ERROR: unauthorized\r\n")
            return
        _terminal_ws_loop(ws, kind, target)


@app.route("/api/servers/register", methods=["POST"])
def api_register_server():
    s = load_settings()
    api_key = request.headers.get("X-API-Key", "")
    if api_key != s.get("server_api_key", ""):
        return json.dumps({"error": "unauthorized"}), 401, {"Content-Type": "application/json"}

    data = request.json
    servers = load_servers()
    ip = data.get("ip", "")

    for srv in servers:
        if srv["ip"] == ip:
            srv.update(data)
            srv["api_key"] = api_key
            srv["last_seen"] = datetime.now().isoformat()
            save_servers(servers)
            # push existing clients to the (re)registered server right away
            threading.Thread(target=lambda: (time.sleep(5), sync_missing_peers_to_secondaries()), daemon=True).start()
            return json.dumps({"status": "updated"}), 200, {"Content-Type": "application/json"}

    data["last_seen"] = datetime.now().isoformat()
    data["enabled"] = True
    data["api_key"] = api_key
    servers.append(data)
    save_servers(servers)
    # push existing clients to the (re)registered server right away
    threading.Thread(target=lambda: (time.sleep(5), sync_missing_peers_to_secondaries()), daemon=True).start()
    return json.dumps({"status": "registered"}), 200, {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Client provisioning API — used by Keenetic Unified (KU) to auto-create a
# unique Phobos client per router (name "ku-<router_id>") and return its
# install command. Each call guarantees a unique WG keypair + tunnel IP +
# peer on ALL servers, so per-router configs never collide.
# ---------------------------------------------------------------------------

CLIENT_SCRIPT = client_script_path()


def _normalize_client_id(name):
    return name.strip().lower().replace(" ", "-")


def _latest_token_for_client(cid):
    try:
        with open(TOKENS_FILE) as f:
            toks = json.load(f)
    except Exception:
        return ""
    for t in reversed(toks):
        if t.get("client") == cid:
            return t.get("token", "")
    return ""


@app.route("/api/client/ensure", methods=["POST"])
def api_client_ensure():
    s = load_settings()
    if request.headers.get("X-API-Key", "") != s.get("server_api_key", ""):
        return json.dumps({"error": "unauthorized"}), 401, {"Content-Type": "application/json"}
    data = request.json or {}
    name = (data.get("name") or "").strip()
    if not name or not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return json.dumps({"error": "bad_name"}), 400, {"Content-Type": "application/json"}
    cid = _normalize_client_id(name)
    env = {**os.environ, **_load_server_env()}
    exists = Path(f"{CLIENTS_DIR}/{cid}").is_dir()
    sub = "link" if exists else "add"
    try:
        out = subprocess.check_output([CLIENT_SCRIPT, sub, name], text=True,
                                      timeout=60, stderr=subprocess.STDOUT, env=env)
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": "script_failed", "output": (e.output or "")[-1500:]}), 500, {"Content-Type": "application/json"}

    meta = next((c for c in get_clients() if c.get("client_id") == cid), None)
    if not meta:
        return json.dumps({"error": "no_meta", "output": out[-800:]}), 500, {"Content-Type": "application/json"}
    pub = meta.get("public_key", "")
    tip = (meta.get("tunnel_ip_v4") or "").split("/")[0]

    # Peer on ALL servers so failover works on every server, not just primary.
    if pub and tip:
        try:
            sync_peer_to_all_servers(pub, f"{tip}/32", "add")
        except Exception:
            pass
    assigned = auto_assign_server(cid)

    # Per-client pull token for the NAT-friendly config pull channel.
    s = load_settings()
    ra = s.get("router_access", {})
    acc = ra.get(cid) or {}
    if not acc.get("pull_token"):
        acc["pull_token"] = secrets.token_hex(16)
        ra[cid] = acc
        s["router_access"] = ra
        save_settings(s)
    pull_token = ra[cid]["pull_token"]

    token = _latest_token_for_client(cid)
    # phobos-client.sh writes these 0600 (umask 077 in action_add) → nginx (www-data)
    # can't read them → 403 on /init and /packages. Make them world-readable.
    if token:
        _www = f"{PHOBOS_DIR}/www"
        for pth in (f"{_www}/init/{token}.sh",
                    f"{_www}/packages/{token}/phobos-{cid}.tar.gz"):
            try:
                os.chmod(pth, 0o644)
            except Exception:
                pass
        try:
            os.chmod(f"{_www}/packages/{token}", 0o755)
        except Exception:
            pass
    install_url = f"{panel_base_url()}/init/{token}.sh" if token else ""
    return json.dumps({
        "ok": True, "client_id": cid, "install_url": install_url, "token": token,
        "install_command": install_command(token) if token else "",
        "pull_token": pull_token, "tunnel_ip": tip, "assigned_server": assigned,
    }), 200, {"Content-Type": "application/json"}


@app.route("/api/client/remove", methods=["POST"])
def api_client_remove():
    s = load_settings()
    if request.headers.get("X-API-Key", "") != s.get("server_api_key", ""):
        return json.dumps({"error": "unauthorized"}), 401, {"Content-Type": "application/json"}
    data = request.json or {}
    cid = _normalize_client_id((data.get("name") or "").strip())
    if not cid:
        return json.dumps({"error": "bad_name"}), 400, {"Content-Type": "application/json"}
    meta = next((c for c in get_clients() if c.get("client_id") == cid), None)
    pub = (meta or {}).get("public_key", "")
    tip = ((meta or {}).get("tunnel_ip_v4") or "").split("/")[0]
    env = {**os.environ, **_load_server_env()}
    try:
        subprocess.check_output([CLIENT_SCRIPT, "remove", cid], text=True,
                                timeout=30, stderr=subprocess.STDOUT, env=env)
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": "script_failed", "output": (e.output or "")[-1500:]}), 500, {"Content-Type": "application/json"}
    if pub and tip:
        try:
            sync_peer_to_all_servers(pub, f"{tip}/32", "remove")
        except Exception:
            pass
    s = load_settings()
    for key in ("router_access", "client_assignments"):
        d = s.get(key, {})
        if cid in d:
            del d[cid]
            s[key] = d
    save_settings(s)
    return json.dumps({"ok": True, "client_id": cid}), 200, {"Content-Type": "application/json"}


@app.route("/api/obf-health")
def api_obf_health():
    """Liveness of the obfuscator path on THIS (primary) server.
    Returns 200 only if all wg-obfuscator-* services are active, else 503.
    Router check_primary uses this as a valid switchback signal (the panel
    HTTP port stays up even when the tunnel path is dead, so it cannot be
    used directly)."""
    try:
        listing = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--no-legend",
             "wg-obfuscator-*"], text=True, timeout=5)
        names = [ln.split()[0] for ln in listing.splitlines() if ln.strip()]
    except Exception:
        names = []
    if not names:
        names = ["wg-obfuscator-2083.service",
                 "wg-obfuscator-5443.service",
                 "wg-obfuscator-993.service"]
    bad = []
    for n in names:
        st = subprocess.getoutput("systemctl is-active " + n).strip()
        if st != "active":
            bad.append(n + "=" + st)
    if bad:
        return "obf-down: " + ",".join(bad), 503, {"Content-Type": "text/plain"}
    return "obf-ok " + str(len(names)), 200, {"Content-Type": "text/plain"}


@app.route("/servers", methods=["GET", "POST"])
@auth_required
def servers_page():
    s = load_settings()
    servers = load_servers()
    msg = ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            ip = request.form.get("ip", "").strip()
            api_key = request.form.get("api_key", "").strip() or s.get("server_api_key", "")
            ssh_user = request.form.get("ssh_user", "root").strip() or "root"
            ssh_pass = request.form.get("ssh_pass", "").strip()
            ssh_port = request.form.get("ssh_port", "22").strip() or "22"
            if ip:
                servers.append({
                    "ip": ip, "api_key": api_key, "enabled": True,
                    "last_seen": "", "wg_public_key": "", "obfuscator_key": "", "ports": "",
                    "ssh_user": ssh_user, "ssh_pass": ssh_pass, "ssh_port": ssh_port
                })
                save_servers(servers)
                order = s.get("server_order", [])
                if ip not in order:
                    order.append(ip)
                    s["server_order"] = order
                    save_settings(s)
                synced = sync_missing_peers_to_secondaries(servers[-1])
                msg = f'<div class="alert alert-ok">Сервер {ip} добавлен, синхронизировано {synced} клиентов</div>'

        elif action == "remove":
            ip = request.form.get("ip", "").strip()
            servers = [sv for sv in servers if sv.get("ip") != ip]
            save_servers(servers)
            order = s.get("server_order", [])
            if ip in order:
                order.remove(ip)
                s["server_order"] = order
                save_settings(s)
            msg = f'<div class="alert alert-ok">Сервер удалён</div>'

        elif action == "sync":
            ip = request.form.get("ip", "").strip()
            srv = next((sv for sv in servers if sv["ip"] == ip), None)
            if srv:
                clients = get_clients()
                synced = 0
                for c in clients:
                    pub = c.get("public_key", "")
                    tip = c.get("tunnel_ip_v4", "")
                    if pub and tip:
                        res = sync_peer_to_server(srv, pub, f"{tip}/32", "add")
                        if res.get("status") == "ok":
                            synced += 1
                msg = f'<div class="alert alert-ok">Синхронизировано {synced} клиентов на {ip}</div>'

        elif action == "fetch_info":
            ip = request.form.get("ip", "").strip()
            for srv in servers:
                if srv["ip"] == ip:
                    try:
                        info = secondary_api_request(srv, "/api/info", timeout=5)
                        srv["wg_public_key"] = info.get("wg_public_key", "")
                        srv["obfuscator_key"] = info.get("obfuscator_key", "")
                        srv["ports"] = ",".join(info.get("ports", []))
                        save_servers(servers)
                        msg = f'<div class="alert alert-ok">Инфо получено от {ip}</div>'
                    except Exception as e:
                        msg = f'<div class="alert alert-error">Ошибка: {e}</div>'

        elif action == "set_api_key":
            new_key = request.form.get("server_api_key", "").strip()
            if new_key:
                s["server_api_key"] = new_key
                save_settings(s)
                msg = '<div class="alert alert-ok">API ключ обновлён</div>'

        elif action in ("move_up", "move_down"):
            ip = request.form.get("ip", "").strip()
            order = s.get("server_order", [])
            if not order or SERVER_IP not in order:
                order = [SERVER_IP] + [sv["ip"] for sv in servers]
            if ip in order:
                idx = order.index(ip)
                if action == "move_up" and idx > 0:
                    order[idx], order[idx-1] = order[idx-1], order[idx]
                elif action == "move_down" and idx < len(order) - 1:
                    order[idx], order[idx+1] = order[idx+1], order[idx]
            s["server_order"] = order
            save_settings(s)

        elif action == "save_router_access":
            clients = get_clients()
            ra = s.get("router_access", {})
            for c in clients:
                cid = c.get("client_id", "")
                ssh_ip = request.form.get(f"ssh_ip_{cid}", "").strip()
                ssh_static = request.form.get(f"ssh_static_{cid}", "").strip()
                ssh_user = request.form.get(f"ssh_user_{cid}", "root").strip() or "root"
                ssh_pass = request.form.get(f"ssh_pass_{cid}", "").strip()
                ssh_port = request.form.get(f"ssh_port_{cid}", "22").strip() or "22"
                web_url = request.form.get(f"web_url_{cid}", "").strip()
                web_login = request.form.get(f"web_login_{cid}", "").strip() or "admin"
                web_pass = request.form.get(f"web_pass_{cid}", "").strip()
                prev = ra.get(cid, {})
                if ssh_ip or ssh_pass or web_url or prev.get("ttyd_token"):
                    ra[cid] = {"ssh_ip": ssh_ip, "ssh_static": ssh_static, "ssh_user": ssh_user,
                               "ssh_pass": ssh_pass, "ssh_port": ssh_port,
                               "web_url": web_url, "web_login": web_login, "web_pass": web_pass,
                               "ttyd_token": prev.get("ttyd_token", ""), "ttyd_ip": prev.get("ttyd_ip", ""),
                               "ttyd_port": prev.get("ttyd_port", "7681"),
                               "ssh_ok": prev.get("ssh_ok", False)}
                elif cid in ra and not ssh_ip and not ssh_pass and not web_url:
                    del ra[cid]
            s["router_access"] = ra
            save_settings(s)
            msg = '<div class="alert alert-ok">SSH доступ сохранён</div>'

        elif action == "test_ssh":
            cid = request.form.get("client_id", "").strip()
            ra = s.get("router_access", {})
            acc = ra.get(cid, {})
            results = []
            ok_ip = ""
            # Try tunnel IP first, then static
            for label, ip in [("tunnel", acc.get("ssh_ip", "")), ("static", acc.get("ssh_static", ""))]:
                if not ip:
                    continue
                try:
                    r = subprocess.run(
                        ["sshpass", "-p", acc.get("ssh_pass", ""), "ssh",
                         "-p", str(acc.get("ssh_port", "22") or "22"), "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                         f"{acc.get('ssh_user','root')}@{ip}", "echo OK"],
                        capture_output=True, text=True, timeout=10
                    )
                    if "OK" in r.stdout:
                        results.append(f"{label} ({ip}): ✓")
                        if not ok_ip:
                            ok_ip = ip
                    else:
                        results.append(f"{label} ({ip}): ✗ {r.stderr[:80]}")
                except Exception as e:
                    results.append(f"{label} ({ip}): ✗ {str(e)[:80]}")
            if cid in ra:
                ra[cid]["ssh_ok"] = bool(ok_ip)
                ra[cid]["ssh_tested"] = ok_ip or ""
                s["router_access"] = ra
                save_settings(s)
            # SSH is optional under the pull model. Frame the result around whether
            # the router is actually reachable/managed, not raw SSH success.
            client_pub = ""
            for _c in get_clients():
                if _c.get("client_id") == cid:
                    client_pub = _c.get("public_key", "")
                    break
            online = False
            for _p, _i in get_wg_peers().items():
                if _p == client_pub and is_peer_online(_i.get("latest handshake", "")):
                    online = True
            for _ip, _hs in server_handshakes_cache.items():
                _ts = _hs.get(client_pub, 0)
                if _ts and (time.time() - _ts) < 180:
                    online = True
            ssh_line = " | ".join(results) if results else tr("SSH не настроен", "SSH not configured")
            if ok_ip:
                msg = f'<div class="alert alert-ok">{cid}: SSH ✓ {ok_ip} — {ssh_line}</div>'
            elif online:
                msg = f'<div class="alert alert-ok">{cid}: {tr("роутер ОНЛАЙН, управляется через pull. SSH по туннелю недоступен — это нормально для роутера за NAT (входящий SSH закрыт); управление SSH не требует.", "router is ONLINE, managed via pull. Tunnel SSH unreachable — normal for a NAT router (inbound SSH closed); management does not need SSH.")}</div>'
            else:
                msg = f'<div class="alert alert-error">{cid}: {tr("роутер НЕ виден — нет свежего handshake ни на одном сервере, и SSH недоступен.", "router NOT visible — no fresh handshake on any server, and SSH unreachable.")} {ssh_line}</div>'

        elif action == "push_all":
            clients = get_clients()
            results = []
            for c in clients:
                cid = c.get("client_id", "")
                res = push_config_to_router(cid)
                results.append(f"{cid}: {res['msg']}")
            msg = '<div class="alert alert-ok">' + '<br>'.join(results) + '</div>'

        elif action == "save_server_access":
            for srv in servers:
                ip = srv["ip"]
                su = request.form.get(f"srv_ssh_user_{ip}", "").strip()
                sp = request.form.get(f"srv_ssh_pass_{ip}", "").strip()
                sport = request.form.get(f"srv_ssh_port_{ip}", "22").strip() or "22"
                if su:
                    srv["ssh_user"] = su
                if sp:
                    srv["ssh_pass"] = sp
                srv["ssh_port"] = sport
            save_servers(servers)
            msg = '<div class="alert alert-ok">SSH доступ к серверам сохранён</div>'

        elif action == "speedtest":
            ip = request.form.get("ip", "").strip()
            res = run_speedtest(ip)
            if res.get("error"):
                msg = f'<div class="alert alert-error">{tr("Замер не удался", "Speed test failed")}: {html_lib.escape(str(res["error"]))}</div>'
            else:
                msg = f'<div class="alert alert-ok">{html_lib.escape(ip)}: ↓ {res.get("download_mbit")} / ↑ {res.get("upload_mbit")} {tr("Мбит/с", "Mbit/s")}, ping {res.get("ping_ms")} ms</div>'

        elif action == "rebalance":
            clients = get_clients()
            all_srv = get_all_servers_ordered()
            server_ips = [sv["ip"] for sv in all_srv]
            # Load-aware greedy: base load from live CPU+RAM (cached by monitor),
            # then each client goes to the least-loaded server, with a per-client
            # penalty so load spreads evenly. Down servers excluded (unless all down).
            base_load = {ip: server_load(server_stats_cache.get(ip, {})) for ip in server_ips}
            usable = [ip for ip in server_ips if base_load[ip] < 0.99] or server_ips
            placed = {ip: 0 for ip in server_ips}
            PEN = 0.08  # extra load each assigned client adds to a server's score
            assignments = {}
            rb_err = []
            for c in clients:
                cid = c["client_id"]
                target = min(usable, key=lambda ip: base_load[ip] + placed[ip] * PEN)
                placed[target] += 1
                assignments[cid] = target
                # Provision the WG peer on the target server. Round-robin assignment
                # alone is not enough — without the peer the handshake fails there and
                # the router's health monitor just fails back.
                pub = c.get("public_key", "")
                tip = c.get("tunnel_ip_v4", "").split("/")[0]
                if pub and tip:
                    r = add_peer_to_server(target, pub, f"{tip}/32")
                    if r.get("status") != "ok":
                        rb_err.append(f"{cid}->{target}: {r.get('msg', 'peer fail')}")
            s["client_assignments"] = assignments
            save_settings(s)
            for _cid in assignments:
                fanout_router_config(_cid)  # push conf to all servers (tunnel pull)
            if rb_err:
                msg = f'<div class="alert alert-error">Rebalance: {"; ".join(rb_err)}</div>'
            else:
                msg = f'<div class="alert alert-ok">{tr("Перераспределено", "Rebalanced")}: {len(clients)} -> {len(server_ips)} {tr("серв.; пиры добавлены, роутеры применят за ~15с", "servers; peers added, routers apply within ~15s")}</div>'

    # Build ordered server list
    all_ordered = get_all_servers_ordered()
    assignments = s.get("client_assignments", {})
    clients = get_clients()

    # Count assigned clients per server
    assign_counts = {}
    for cid, sip in assignments.items():
        assign_counts[sip] = assign_counts.get(sip, 0) + 1

    # Stats dashboard cards
    stats_cards = ""
    for srv in all_ordered:
        ip = srv.get("ip", "")
        is_primary = srv.get("is_primary", False)
        cached = server_stats_cache.get(ip, {})
        ports = srv.get("ports", "?")
        assigned = assign_counts.get(ip, 0)

        if is_primary:
            local = get_local_stats()
            cpu_val = local.get("cpu", "?")
            mem_val = local.get("mem", "?")
            peers_val = local.get("peers", 0)
            mbps_val = local.get("mbps", 0.0)
            st_class = "badge-on"
            st_text = "Primary"
        else:
            cpu_val = cached.get("cpu", "—")
            mem_val = cached.get("mem", "—")
            peers_val = cached.get("peers", "?")
            mbps_val = cached.get("mbps", 0.0)
            is_up = cached.get("status", "down") == "ok"
            st_class = "badge-on" if is_up else "badge-off"
            st_text = "Online" if is_up else "Offline"
        term_target = "main" if is_primary else ip
        term_btn = _terminal_button(f"/terminal/server/{term_target}", tr("SSH терминал сервера", "Server SSH terminal"))
        _offline = (not is_primary) and (cached.get("status", "down") != "ok")
        mbps_disp = "—" if _offline else f"{mbps_val} Mbps"
        _st = load_settings().get("speedtests", {}).get(ip, {})
        speed_line = (f'⚡ ↓ <b style="color:var(--text)">{_st.get("download_mbit")}</b> / ↑ <b style="color:var(--text)">{_st.get("upload_mbit")}</b> {tr("Мбит/с", "Mbit/s")} · '
                      f'{datetime.fromtimestamp(int(_st.get("ts", 0))).strftime("%d.%m %H:%M")}') if _st.get("ts") else ""
        country = _ip_country(ip)
        country_html = f'<span style="font-size:.8em;color:var(--muted);margin-left:6px">{country}</span>' if country else ""

        stats_cards += f"""
        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:200px;flex:1">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span><b style="color:var(--accent)">{ip}</b>{country_html}</span>
            <span style="display:flex;gap:6px;align-items:center">{term_btn}<span class="badge {st_class}">{st_text}</span></span>
          </div>
          <div style="font-size:.82em;color:var(--muted);line-height:1.8">
            CPU: <b style="color:var(--text)">{cpu_val}</b> &nbsp; RAM: <b style="color:var(--text)">{mem_val}</b><br>
            Peers: <b style="color:var(--text)">{peers_val}</b> &nbsp; Assigned: <b style="color:var(--text)">{assigned}</b> &nbsp; Ports: {ports}<br>
            <span title="Канал / Channel (rx+tx)">↕ <b style="color:var(--text)">{mbps_disp}</b></span><br>
            {speed_line}
          </div>
          <form method="post" style="margin-top:8px" onsubmit="this.querySelector('button').textContent='⏳ ~20 s…'">
            <input type="hidden" name="action" value="speedtest"><input type="hidden" name="ip" value="{ip}">
            <button class="btn btn-sm btn-primary" type="submit">⚡ {tr("Замер скорости", "Speed test")}</button>
          </form>
        </div>"""

    # Server priority rows
    rows = ""
    for idx, srv in enumerate(all_ordered):
        ip = srv.get("ip", "")
        is_primary = srv.get("is_primary", False)
        ports = srv.get("ports", "?")
        cached = server_stats_cache.get(ip, {})
        peers_val = cached.get("peers", get_local_stats().get("peers", "?") if is_primary else "?")
        assigned = assign_counts.get(ip, 0)

        if is_primary:
            st_class, st_text = "badge-on", "Primary"
        else:
            is_up = cached.get("status", "down") == "ok"
            st_class = "badge-on" if is_up else "badge-off"
            st_text = "Online" if is_up else "Offline"

        prio = f'<span style="color:#6366f1;font-weight:600;margin-right:6px">#{idx+1}</span>'
        ptag = ' <span class="badge" style="background:#312e81;color:var(--accent)">Primary</span>' if is_primary else ""

        mv = f"""<button name="action" value="move_up" class="btn btn-sm" style="background:#334155;padding:2px 8px" {"disabled" if idx==0 else ""}>▲</button>
            <button name="action" value="move_down" class="btn btn-sm" style="background:#334155;padding:2px 8px" {"disabled" if idx==len(all_ordered)-1 else ""}>▼</button>"""

        acts = ""
        term_target = "main" if is_primary else ip
        term_btn = _terminal_button(f"/terminal/server/{term_target}", tr("SSH терминал сервера", "Server SSH terminal"))
        if not is_primary:
            acts = f"""<button name="action" value="sync" class="btn btn-primary btn-sm">{tr("Синхр.","Sync")}</button>
            <button name="action" value="fetch_info" class="btn btn-primary btn-sm">{tr("Инфо","Info")}</button>
            <button name="action" value="remove" class="btn btn-danger btn-sm" onclick="return confirm('{tr("Удалить сервер?","Remove server?")}')">{tr("Удалить","Del")}</button>"""

        rows += f"""<tr>
        <td>{prio}{ip}{ptag}</td><td>{ports}</td><td>{peers_val}</td><td>{assigned}</td>
        <td><span class="badge {st_class}">{st_text}</span></td>
        <td><form method="post" style="display:inline"><input type="hidden" name="ip" value="{ip}">{mv} {term_btn} {acts}</form></td>
        </tr>"""

    api_key = s.get("server_api_key", "")

    # Router access rows — tunnel IP + optional static IP
    router_access = s.get("router_access", {})
    access_rows = ""
    for c in clients:
        cid = c.get("client_id", "")
        tunnel_ip = c.get("tunnel_ip_v4", "")
        acc = router_access.get(cid, {})
        ssh_ip = acc.get("ssh_ip", tunnel_ip)
        ssh_static = acc.get("ssh_static", "")
        ssh_user = acc.get("ssh_user", "root")
        ssh_pass = acc.get("ssh_pass", "")
        ssh_port = acc.get("ssh_port", "22")
        web_url = acc.get("web_url", "")
        web_login = acc.get("web_login", "")
        web_pass = acc.get("web_pass", "")
        ssh_ok = acc.get("ssh_ok", False)
        ssh_tested = acc.get("ssh_tested", "")
        if ssh_ok:
            badge_cls = "badge-on"
            badge_txt = f"✓ {ssh_tested}" if ssh_tested else "✓"
        elif ssh_ip and ssh_pass:
            badge_cls = "badge-warn"
            badge_txt = "не проверен"
        else:
            badge_cls = "badge-off"
            badge_txt = "—"
        access_rows += f"""<tr>
        <td>{cid}</td>
        <td><input type="text" name="ssh_ip_{cid}" value="{ssh_ip}" placeholder="{tunnel_ip}" style="min-width:130px;padding:4px" title="WG tunnel IP"></td>
        <td><input type="text" name="ssh_static_{cid}" value="{ssh_static}" placeholder="static" style="min-width:150px;padding:4px" title="Static/public IP (optional)"></td>
        <td><input type="text" name="ssh_user_{cid}" value="{ssh_user}" placeholder="root" style="min-width:90px;padding:4px"></td>
        <td><input type="number" name="ssh_port_{cid}" value="{ssh_port}" placeholder="22" min="1" max="65535" style="min-width:80px;padding:4px"></td>
        <td><input type="password" name="ssh_pass_{cid}" value="{ssh_pass}" placeholder="pass" style="min-width:120px;padding:4px"></td>
        <td><input type="text" name="web_url_{cid}" value="{web_url}" placeholder="keendns.url" style="min-width:230px;padding:4px" title="KeenDNS URL for RCI console"></td>
        <td><input type="text" name="web_login_{cid}" value="{web_login}" placeholder="admin" style="min-width:105px;padding:4px"></td>
        <td><input type="password" name="web_pass_{cid}" value="{web_pass}" placeholder="web pass" style="min-width:125px;padding:4px"></td>
        <td><span class="badge {badge_cls}" style="font-size:.7em">{badge_txt}</span></td>
        </tr>"""

    html = f"""
    <div class="container">
    {nav('servers')}
    {msg}

    <div class="card">
    <h2>{tr("Панель серверов", "Server Dashboard")} {hlp("Живая статистика всех VPN-серверов. Peers = активные WG-подключения. Assigned = клиенты, у которых этот сервер основной. Фоновый монитор опрашивает каждые " + str(s.get('monitor_interval',30)) + " сек и шлёт оповещения в Telegram при падении/восстановлении сервера.", "Live stats for all VPN servers. Peers = active WG connections. Assigned = clients whose primary is this server. Background monitor polls every " + str(s.get('monitor_interval',30)) + "s and sends Telegram alerts on server up/down.")}</h2>
    <div style="display:flex;gap:12px;flex-wrap:wrap">{stats_cards}</div>
    </div>

    <div class="card">
    <h2>{tr("Приоритет серверов и балансировка", "Server Priority & Load Balancing")} {hlp("У каждого клиента есть основной сервер. При сбое роутер сам перебирает серверы сверху вниз. Стрелки меняют общий порядок резервирования. Роутеры за NAT подтягивают конфиг сами — ручных действий не нужно.", "Each client has a primary server. On failure the router tries servers top-to-bottom by itself. Arrows change the global fallback order. NAT routers pull config themselves — no manual action needed.")}</h2>
    <div class="table-wrap"><table class="wide-table">
    <tr><th>{tr("Сервер","Server")}</th><th>{tr("Порты","Ports")}</th><th>Peers</th><th>{tr("Назначено","Assigned")}</th><th>{tr("Статус","Status")}</th><th>{tr("Действия","Actions")}</th></tr>
    {rows}
    </table></div>
    <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <form method="post" style="display:inline"><input type="hidden" name="action" value="rebalance">
    <button class="btn btn-primary" type="submit" onclick="return confirm('{tr("Перераспределить всех клиентов по серверам?","Redistribute all clients across servers?")}')">{tr("Балансировать","Rebalance")}</button></form>
    {hlp("Равномерно распределить всех клиентов по серверам (round-robin). Меняет основной сервер у клиентов — они переключатся автоматически.", "Evenly redistribute all clients across servers (round-robin). Changes clients primary server — they switch automatically.")}
    <form method="post" style="display:inline"><input type="hidden" name="action" value="push_all">
    <button class="btn btn-primary" type="submit" onclick="return confirm('{tr("Отправить конфиг на все роутеры?","Push config to all routers?")}')">Push All</button></form>
    {hlp("Принудительно отправить конфиг на роутеры с прямым SSH. Роутеры за NAT это игнорируют и сами подтягивают конфиг за ~15 сек — обычно эта кнопка не нужна.", "Force-push config to routers reachable by SSH. NAT routers ignore it and auto-pull within ~15s — you usually do not need this.")}
    </div>
    <form method="post" class="form-row" style="margin-top:16px;flex-wrap:wrap">
    <input type="hidden" name="action" value="add">
    <input type="text" name="ip" placeholder="{tr('IP сервера','Server IP')}" required>
    <input type="text" name="api_key" placeholder="{tr('API key (пусто = главный)','API key (blank = main)')}" style="width:190px">
    <input type="text" name="ssh_user" placeholder="root" style="width:70px" value="root">
    <input type="number" name="ssh_port" placeholder="22" value="22" min="1" max="65535" style="width:80px">
    <input type="password" name="ssh_pass" placeholder="SSH pass" style="width:140px">
    <button class="btn btn-primary" type="submit">{tr("Добавить сервер","Add Server")}</button>
    {hlp("Добавить новый VPN-сервер в пул резервирования. Если secondary ставился командой ниже, API key можно оставить пустым — будет использован главный ключ панели. 8444 — это порт mini-API, не ключ.", "Add a new VPN server to the failover pool. If the secondary was installed with the command below, API key may be left blank — the panel main key will be used. 8444 is the mini-API port, not the key.")}
    </form>
    </div>

    <div class="card">
    <h2>{tr("Доступ к роутерам — SSH / RCI (опционально)", "Router access — SSH / RCI (optional)")} {hlp("НЕ обязательно для работы VPN (роутеры сами тянут конфиг по HTTP/HTTPS через pull). SSH-поля — для роутеров с прямым IP (мгновенный push). KeenDNS URL + web-логин/пароль — для RCI-консоли Keenetic (кнопка 🛠 RCI у клиента): управление ndmc-командами через KeenDNS, работает за NAT без SSH. Для Keenetic за NAT используй именно RCI (SSH к ним недоступен).", "NOT required for VPN (routers auto-pull config over HTTP/HTTPS). SSH fields — for direct-IP routers (instant push). KeenDNS URL + web login/password — for the Keenetic RCI console (🛠 RCI button): run ndmc commands via KeenDNS, works behind NAT without SSH. For NAT Keenetic use RCI (SSH is unreachable).")}</h2>
    <form method="post">
    <input type="hidden" name="action" value="save_router_access">
    <div class="table-wrap"><table class="router-access-table">
    <tr><th>{tr("Клиент","Client")}</th><th>Tunnel IP</th><th>{tr("Статич. IP","Static IP")}</th><th>{tr("Пользователь","User")}</th><th>{tr("Порт","Port")}</th><th>{tr("Пароль","Pass")}</th><th>KeenDNS URL</th><th>web {tr("логин","login")}</th><th>web {tr("пароль","pass")}</th><th>{tr("Статус","Status")}</th></tr>
    {access_rows}
    </table></div>
    <button class="btn btn-primary" type="submit" style="margin-top:10px">{tr("Сохранить SSH","Save SSH")}</button>
    {hlp("Сохранить SSH-доступ к роутерам. Нужно только для роутеров с прямым публичным IP. Для NAT-роутеров не требуется.", "Save SSH access to routers. Only needed for routers with a direct public IP. Not required for NAT routers.")}
    </form>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
    {"".join(f'<form method="post" style="display:inline"><input type="hidden" name="action" value="test_ssh"><input type="hidden" name="client_id" value="{c.get("client_id","")}"><button class="btn btn-sm" style="background:#334155;padding:4px 12px;font-size:.8em" type="submit">{tr("Тест","Test")} {c.get("client_id","")}</button></form>' for c in clients)}
    </div>
    </div>

    <div class="card">
    <h2>Server SSH Access</h2>
    <p style="color:var(--muted);font-size:.85em;margin-bottom:12px">SSH credentials for secondary servers. Used by panel to add/remove WG peers when switching client servers. Main server uses local commands.</p>
    <form method="post">
    <input type="hidden" name="action" value="save_server_access">
    <div class="table-wrap"><table class="wide-table">
    <tr><th>Server</th><th>SSH User</th><th>SSH Port</th><th>SSH Pass</th><th></th></tr>
    {"".join(f'''<tr>
    <td>{srv.get("ip","")}</td>
    <td><input type="text" name="srv_ssh_user_{srv.get('ip','')}" value="{srv.get('ssh_user','root')}" placeholder="root" style="width:80px;padding:4px"></td>
    <td><input type="number" name="srv_ssh_port_{srv.get('ip','')}" value="{srv.get('ssh_port','22')}" placeholder="22" min="1" max="65535" style="width:80px;padding:4px"></td>
    <td><input type="password" name="srv_ssh_pass_{srv.get('ip','')}" value="{srv.get('ssh_pass','')}" placeholder="pass" style="width:150px;padding:4px"></td>
    <td><span class="badge {'badge-on' if srv.get('ssh_pass') else 'badge-off'}">{'OK' if srv.get('ssh_pass') else '—'}</span></td>
    </tr>''' for srv in servers)}
    </table></div>
    <button class="btn btn-primary" type="submit" style="margin-top:10px">Save Server SSH</button>
    </form>
    </div>

    <div class="card">
    <h2>API Key</h2>
    <form method="post" class="form-row">
    <input type="hidden" name="action" value="set_api_key">
    <input type="text" name="server_api_key" value="{api_key}" placeholder="API key" style="width:300px">
    <button class="btn btn-primary" type="submit">Save</button>
    </form>
    </div>

    <div class="card">
    <h2>Deploy Secondary Server</h2>
    <p style="color:var(--muted);font-size:.85em;margin-bottom:8px">One command deploys WG + obfuscator + mini-API on a new VPS. Auto-registers in panel. Run via SSH on new VPS:</p>
    <code style="background:var(--bg);padding:8px 12px;border-radius:6px;display:block;font-size:.82em;word-break:break-all">MAIN_PROTO={panel_scheme()} MAIN_SERVER={SERVER_IP} MAIN_PORT={panel_port()} MAIN_API_KEY={api_key} bash &lt;(curl -kfsSL {panel_base_url()}/server/secondary-setup.sh)</code>
    </div>
    </div>"""
    return render(html)
if __name__ == "__main__":
    ssl_context = None
    cert = os.environ.get("PANEL_TLS_CERT", "")
    key = os.environ.get("PANEL_TLS_KEY", "")
    if panel_scheme() == "https" and cert and key:
        ssl_context = (cert, key)
    app.run(host="0.0.0.0", port=int(panel_port()), debug=False, ssl_context=ssl_context)
