#!/usr/bin/env python3
"""Phobos Secondary Server API — peer management + health."""
import json, os, subprocess, time, hmac
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

def load_env():
    env = {}
    with open("/opt/Phobos/server/server.env") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v
    return env

def check_api_key():
    env = load_env()
    key = request.headers.get("X-API-Key", "")
    return hmac.compare_digest(key, env.get("MAIN_API_KEY", ""))


def default_iface():
    try:
        out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True, timeout=4)
        parts = out.split()
        for i, part in enumerate(parts[:-1]):
            if part == "dev":
                return parts[i + 1].strip()
    except Exception:
        pass
    return ""


def cpu_percent():
    try:
        with open("/proc/stat") as fh:
            a = fh.readline().split()[1:]
        time.sleep(0.1)
        with open("/proc/stat") as fh:
            b = fh.readline().split()[1:]
        a = [int(x) for x in a]
        b = [int(x) for x in b]
        idle = b[3] - a[3]
        total = sum(b) - sum(a)
        if total <= 0:
            return "?"
        return f"{round(100 - (idle * 100.0 / total), 1)}%"
    except Exception:
        return "?"

def net_bytes():
    try:
        iface = default_iface()
        with open("/proc/net/dev") as fh:
            for line in fh:
                if line.split(":")[0].strip() == iface:
                    p = line.split(":")[1].split()
                    return {"iface": iface, "rx": int(p[0]), "tx": int(p[8]), "ts": int(time.time())}
    except Exception:
        pass
    return {}


@app.route("/api/health")
def health():
    try:
        out = subprocess.check_output(["wg", "show", "wg0", "dump"], text=True, timeout=5)
        peer_keys = []
        handshakes = {}
        transfer = {}
        for line in out.strip().split("\n")[1:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                pub = parts[0]
                peer_keys.append(pub)
                try:
                    transfer[pub] = [int(parts[5]), int(parts[6])]
                except Exception:
                    pass
                try:
                    handshakes[pub] = int(parts[4])
                except Exception:
                    handshakes[pub] = 0
        peers = len(peer_keys)
    except Exception:
        peers = 0
        peer_keys = []
        handshakes = {}
        transfer = {}
    cpu = cpu_percent()
    try:
        parts = Path("/proc/meminfo").read_text().splitlines()
        vals = {}
        for line in parts:
            k, v = line.split(":", 1)
            vals[k] = int(v.strip().split()[0])
        total = vals.get("MemTotal", 0) // 1024
        avail = vals.get("MemAvailable", 0) // 1024
        used = max(total - avail, 0)
        mem_str = f"{used}/{total}MB"
    except Exception:
        mem_str = "?"
    return jsonify({"status": "ok", "peers": peers, "peer_keys": peer_keys, "handshakes": handshakes, "transfer": transfer, "cpu": cpu, "mem": mem_str, "net": net_bytes()})


@app.route("/api/obf-health")
def obf_health():
    """Return 200 only when all local wg-obfuscator-* services are active."""
    try:
        listing = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--no-legend",
             "wg-obfuscator-*"], text=True, timeout=5)
        names = [ln.split()[0] for ln in listing.splitlines() if ln.strip()]
    except Exception:
        names = []
    if not names:
        env = load_env()
        ports = [p.strip() for p in env.get("OBFUSCATOR_PORTS", "2083,5443,993").split(",") if p.strip()]
        names = [f"wg-obfuscator-{p}.service" for p in ports]
    bad = []
    for name in names:
        status = subprocess.getoutput("systemctl is-active " + name).strip()
        if status != "active":
            bad.append(name + "=" + status)
    if bad:
        return ("obf-down: " + ",".join(bad), 503, {"Content-Type": "text/plain"})
    return ("obf-ok " + str(len(names)), 200, {"Content-Type": "text/plain"})


@app.route("/api/peers", methods=["GET"])
def list_peers():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    try:
        out = subprocess.check_output(["wg", "show", "wg0", "allowed-ips"], text=True, timeout=5)
        peers = {}
        for line in out.strip().split("\n"):
            if "\t" in line:
                pub, ips = line.split("\t", 1)
                peers[pub.strip()] = ips.strip()
        return jsonify({"peers": peers})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


LIMIT_SCRIPT = "/opt/Phobos/server/phobos-limit.sh"


def ensure_script(path):
    """Fetch a helper script from the main panel if this agent predates it."""
    if os.path.exists(path):
        return
    env = load_env()
    url = "%s://%s:%s/server/%s" % (env.get("MAIN_PROTO", "http"), env.get("MAIN_SERVER", ""),
                                    env.get("MAIN_PORT", ""), os.path.basename(path))
    subprocess.run(["curl", "-kfsSL", "-m", "20", url, "-o", path], timeout=30)
    if os.path.exists(path):
        os.chmod(path, 0o755)


@app.route("/api/speedtest", methods=["POST"])
def speedtest():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    path = "/opt/Phobos/server/phobos-speedtest.sh"
    ensure_script(path)
    try:
        r = subprocess.run([path], capture_output=True, text=True, timeout=80)
        return jsonify(json.loads(r.stdout.strip().splitlines()[-1]))
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# --- Google geo (09.30): how Google sees the server's addresses ---------------
GOOGLE_CLOSED = {"Russia", "Belarus", "China", "Iran", "Hong Kong", "North Korea", "Cuba", "Syria"}


def _google_country(*args):
    """«Country version» at the bottom of policies.google.com/terms = the country Google assigns to the address."""
    import re as _re
    import subprocess as _sp
    try:
        html = _sp.run(["curl", *args, "-s", "-m", "15", "https://policies.google.com/terms?hl=en"],
                       capture_output=True, text=True, timeout=25).stdout
        m = _re.search(r"Country version:\s*</a>\s*([A-Za-z][A-Za-z .'-]*?)\s*<", html)
        return m.group(1) if m else None
    except Exception:
        return None


def google_geo():
    """v4/v6 = default route (what clients exit with); ips = every public IPv4 on the server."""
    import re as _re
    import subprocess as _sp
    import time as _t
    out = {"v4": _google_country("-4"), "v6": _google_country("-6"), "ips": {}, "ts": int(_t.time())}
    try:
        for line in _sp.run(["ip", "-4", "-o", "addr", "show", "scope", "global"], capture_output=True,
                            text=True, timeout=10).stdout.splitlines():
            ip = line.split()[3].split("/")[0]
            if not _re.match(r"^(10|127|172\.(1[6-9]|2\d|3[01])|192\.168|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.", ip):
                out["ips"][ip] = _google_country("-4", "--interface", ip)
    except Exception:
        pass
    return out


@app.route("/api/google-geo")
def api_google_geo():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(google_geo())


@app.route("/api/limits", methods=["POST"])
def set_limits():
    """Per-client speed limits pushed by the main panel ("<tunnel_ip> <mbit>" lines)."""
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    text = (request.get_json(force=True, silent=True) or {}).get("limits", "")
    Path("/opt/Phobos/server/limits.conf").write_text(text)
    ensure_script(LIMIT_SCRIPT)
    try:
        r = subprocess.run([LIMIT_SCRIPT, "apply"], capture_output=True, text=True, timeout=30)
        return jsonify({"status": "ok" if r.returncode == 0 else "error", "out": (r.stdout + r.stderr)[-500:]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/peers/add", methods=["POST"])
def add_peer():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    pub_key = data.get("public_key", "")
    allowed_ips = data.get("allowed_ips", "")
    if not pub_key or not allowed_ips:
        return jsonify({"error": "missing public_key or allowed_ips"}), 400
    try:
        subprocess.run(["wg", "set", "wg0", "peer", pub_key, "allowed-ips", allowed_ips], check=True, timeout=5)
        subprocess.run(["wg-quick", "save", "wg0"], timeout=5)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/peers/remove", methods=["POST"])
def remove_peer():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    pub_key = data.get("public_key", "")
    if not pub_key:
        return jsonify({"error": "missing public_key"}), 400
    try:
        subprocess.run(["wg", "set", "wg0", "peer", pub_key, "remove"], check=True, timeout=5)
        subprocess.run(["wg-quick", "save", "wg0"], timeout=5)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/info")
def info():
    if not check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    env = load_env()
    return jsonify({
        "ip": env.get("SERVER_PUBLIC_IP_V4"),
        "wg_public_key": env.get("SERVER_WG_PUBLIC_KEY"),
        "obfuscator_key": env.get("OBFUSCATOR_KEY"),
        "ports": env.get("OBFUSCATOR_PORTS", "2083").split(","),
        "role": "secondary"
    })

ROUTER_CONFIGS_DIR = "/opt/Phobos/server/router-configs"


@app.route("/api/router-config/<client_id>")
def router_config(client_id):
    """Serve a client's failover.conf so routers can PULL via the tunnel
    (http://<server-tunnel-ip>:8444/...). Token via ?token= or X-API-Key."""
    token = request.args.get("token", "") or request.headers.get("X-API-Key", "")
    if token != load_env().get("MAIN_API_KEY", ""):
        return ("forbidden", 403)
    path = os.path.join(ROUTER_CONFIGS_DIR, client_id + ".conf")
    if not os.path.exists(path):
        return ("not found", 404)
    with open(path) as fh:
        return (fh.read(), 200, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/api/router-config-set", methods=["POST"])
def router_config_set():
    """Panel fan-out: store a client's failover.conf on this server."""
    if not check_api_key():
        return jsonify({"status": "error", "msg": "unauthorized"}), 403
    data = request.get_json(force=True, silent=True) or {}
    cid = data.get("client_id", "")
    conf = data.get("conf", "")
    if not cid or "SERVER_1=" not in conf:
        return jsonify({"status": "error", "msg": "bad payload"}), 400
    os.makedirs(ROUTER_CONFIGS_DIR, exist_ok=True)
    with open(os.path.join(ROUTER_CONFIGS_DIR, cid + ".conf"), "w") as fh:
        fh.write(conf)
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8444)
