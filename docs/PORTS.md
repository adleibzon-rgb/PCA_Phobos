# PCA Phobos ports and firewall checklist

This page is the short truth table for normal Phobos work. Use it before
opening a ticket about "router does not switch", "secondary is online but sync
fails", or "panel is too exposed".

## Primary server

| Port | Protocol | Who connects | Required | Why |
| --- | --- | --- | --- | --- |
| `PANEL_PORT` | TCP | admin browser, secondary setup/register, router pull fallback | yes | Web panel and `/api/*`. Real value: `cat /opt/phobos-panel/.port`. |
| `80` | TCP | routers during install, Android APK download | recommended | nginx serves `/init/`, `/packages/`, `/app/`. |
| `2083,5443,993` | UDP | routers and Android PhobosWG | yes | wg-obfuscator public entry ports. Real value: `grep OBFUSCATOR_PORTS /opt/Phobos/server/server.env`. |
| `443` (else `8443`/`2096`/`4433`) | TCP | PCA Phobos VPN apps, Windows, routers (1.5.0+) when UDP is blocked | recommended | TCP fallback `phobos-tcp` (udptcp) since 1.4.1; port chosen at install/update, shown in `phobos-update` output (`TCP fallback: port N`). |
| second public IP: obfuscator ports + TCP | UDP/TCP | routers whose ISP blocks the main IP | optional | `phobos-altip` (1.5.0) DNATs the second IP to the main one; list it in panel → «Адрес для клиентов» → spare addresses. |
| `51820` | UDP | plain WireGuard clients only | no by default | Usually blocked to force obfuscation. Open only if installed with `ALLOW_PLAIN_WG=1` for iOS/plain WG. |
| `22` | TCP | admin only | optional | SSH maintenance. Do not expose broadly. |

`PANEL_PORT` is random on clean install unless passed as env:

```bash
cat /opt/phobos-panel/.port
```

## Secondary server

| Port | Protocol | Who connects | Required | Why |
| --- | --- | --- | --- | --- |
| `8444` | TCP | primary panel, routers via tunnel/public path | yes | Mini-API: health, peer sync, router config cache. |
| `2083,5443,993` | UDP | routers and Android PhobosWG | yes | wg-obfuscator public entry ports. |
| `51820` | UDP | nobody public | no | WireGuard listens locally behind obfuscator; public access is blocked. |
| `22` | TCP | admin during install | optional | SSH maintenance. |

If secondary is "Online" but `Info`, `Sync`, or client assignment fails, check
`8444/tcp` first and confirm the API key matches the main panel key.

## Router outbound access

Routers need outbound access to:

- every server UDP obfuscator port, default `2083,5443,993`;
- primary `PANEL_PORT/tcp` for initial install and public pull fallback;
- primary `80/tcp` if using the nginx install fallback;
- tunnel management paths after VPN is up:
  - `http://10.25.0.1:8444` for secondary mini-API;
  - `http(s)://10.25.0.1:<PANEL_PORT>` for primary panel API.

Current router packages write these files on the router:

```bash
/opt/etc/Phobos/panel_url
/opt/etc/Phobos/panel_urls
/opt/etc/Phobos/panel_port
/opt/etc/Phobos/panel_scheme
```

If a router does not switch after changing its server in the panel, check:

```bash
cat /opt/etc/Phobos/panel_urls
cat /opt/etc/Phobos/failover.conf
tail -n 80 /opt/etc/Phobos/health.log
/opt/etc/Phobos/phobos-pull.sh
```

If `panel_urls` contains an old IP or old panel port, create a fresh install
command in the panel and reinstall/update that router package.

## HTTPS panel

Native HTTPS is supported by the primary installer:

```bash
PANEL_TLS_CERT=/etc/letsencrypt/live/example.com/fullchain.pem \
PANEL_TLS_KEY=/etc/letsencrypt/live/example.com/privkey.pem \
bash <(curl -fsSL https://git.bobyrev.com/PCA/PCA_Phobos/raw/branch/main/install.sh)
```

Then the panel runs as:

```text
https://<server-ip>:<PANEL_PORT>
```

The generated router and secondary commands use `curl -k`/`wget
--no-check-certificate` fallback so a self-signed certificate can work for
bootstrap. For humans in a browser, use a real certificate to avoid warnings.

## Can I IP-whitelist the panel port?

Yes, but with care. `PANEL_PORT` is not only the admin UI. It also carries
server registration and router pull API. If you whitelist it too tightly, these
features break:

- secondary auto-register;
- `Info` / `Sync` / client assignment to secondary;
- router pull fallback before tunnel is up;
- router config update when public path is the only available path.

Minimum allowlist for `PANEL_PORT`:

- your admin IPs;
- all secondary server public IPs;
- router public IPs, if they are static;
- or no router IP restriction until first install is complete and tunnel pull is proven.

For CGNAT/dynamic-router fleets, do not rely on a strict public-IP allowlist for
router management. Use strong panel password, API key secrecy, optional HTTPS,
and keep only the required ports open.
