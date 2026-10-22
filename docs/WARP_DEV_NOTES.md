# WARP in `dev` — modes, checks, current limits

Date: `2026-06-06`
Channel: `dev`
Version: `v1.3.1-dev`

## What was added

The `dev` panel now has a dedicated `WARP / WARP+` block in `/settings`.

Supported modes:

- `egress` — route client outbound traffic through WARP on the server side;
- `relay` — expose a UDP relay for a separate WARP/WireGuard client profile;
- `custom profile` — save a full custom `warp.conf` from the web UI;
- `WARP+ key` — save a license key and rebuild the profile through `wgcf`.

The UI also has a `?` help block with plain-language explanations:

- what each mode does;
- when to use `free` vs `custom`;
- what `WARP+ key` changes;
- what `Enable` and `Disable` do;
- how per-client WARP works from the client list.

## How the modes work

### `egress`

Use this when you want Phobos clients to keep connecting the usual way, but send
their outgoing traffic through Cloudflare WARP after they land on the server.

Implementation:

- WireGuard clients still connect to the Phobos server;
- server-side policy routing sends only selected client tunnel IPs through `warp`;
- NAT is done with `POSTROUTING MASQUERADE`;
- client rows in `/clients` have `WARP ON/OFF`, which adds/removes `ip rule from <client-ip>/32`.

### `relay`

Use this when you need a separate relay endpoint for another WARP/WireGuard
client profile.

Important:

- this is **not** a drop-in replacement for the normal Phobos router config;
- the client must use a separate WARP/WireGuard profile aimed at the relay port;
- this mode is for relay-style scenarios, not for replacing the regular
  `home.conf` path one-to-one.

Implementation:

- UDP relay rules are added with tagged iptables entries;
- incoming UDP on the selected port is DNAT'ed to the target WARP endpoint;
- outgoing packets are MASQUERADE'd back through the relay host.

### `custom profile` and `WARP+`

Two ways to use a non-default profile:

- paste a full custom `warp.conf`;
- save a `WARP+ key` and let `wgcf` rebuild the profile from it.

This keeps the UI simple:

- `free WARP` still works out of the box;
- `WARP+` is possible when the owner has a real key;
- no hidden magic is required outside the panel.

## Live checks completed

### Server-side checks

Passed:

- `python3 -m py_compile app.py server/api.py`
- `bash -n install.sh update.sh server/phobos-warp.sh`
- live `status` checks on dev server `64.188.81.115`

Verified on the dev server:

- `egress` mode enables cleanly;
- current egress IPv4 is reported in status JSON;
- `custom profile` and `WARP+ key` save from the web UI;
- relay rules appear with separate tagged iptables entries.

### Real router check

Router used for testing:

- public SSH: `95.72.5.253`
- web: `https://homesmart.netcraze.pro/dashboard`

Confirmed:

- real router traffic was sent through the dev server;
- with `egress` enabled, a live `curl https://api.ipify.org` from the router
  returned WARP egress IP `104.28.193.219`;
- this proves the real data path for `router -> Phobos -> WARP -> internet`.

### Relay check

Confirmed:

- relay mode enables from the server side;
- relay iptables rules are created;
- counters increase on live traffic;
- a separate WARP profile pointed at the relay port completes handshake.

Not fully closed yet:

- relay handshake and packet flow were confirmed;
- a full end-to-end "internet works through relay profile" check on the router
  was not fully finished in a clean state before router access became limited.

## Router recovery note

During live tests, WAN SSH access to the router stopped responding, so full file
restore over shell was blocked.

What was still restored safely:

- temporary KeenDNS helper proxies created for testing were removed;
- temporary extra WireGuard peer entries were cleaned up;
- the router is currently left on a **working direct dev WireGuard peer** so it
  stays reachable through the test tunnel rather than returning to a broken
  down state.

What still needs one final shell pass later:

- restore `/opt/etc/Phobos/home.conf` from backup;
- restore `/opt/etc/Phobos/wg-obfuscator.conf` from backup;
- restore `/opt/etc/Phobos/failover.conf` from backup;
- restore minute cron jobs for `phobos-health.sh` and `phobos-pull.sh`.

Known backup path on the router:

- `/opt/etc/Phobos/test-backup-20260606-044834`

## Current honest status

Ready now:

- `egress` mode
- per-client `WARP ON/OFF`
- `custom profile`
- `WARP+ key`
- UI help text

Partially verified:

- `relay` mode

Extra audit fixes after live testing:

- orphan WireGuard peers now show up in both `Sessions` and `Clients` as `orphan-*` instead of disappearing into `unknown`;
- orphan rows can be `Kick`ed, `Purge`d, and also toggled through per-peer WARP;
- client package build no longer fails when `/opt/Phobos/bin` is missing or `OBFUSCATOR_KEY` is empty;
- update / restore scripts now restart the active panel service automatically (`phobos-panel` or `phobos-dev-test`).
