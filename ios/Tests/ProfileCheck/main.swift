// Self-check of phobos:// parsing (no device needed):
//   cd ios/Tests/ProfileCheck && xcrun swiftc -o /tmp/pc ../../Shared/PhobosProfile.swift main.swift && /tmp/pc
import Foundation
let conf = """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.25.0.9/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = none
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[instance]
source-if = 127.0.0.1
source-lport = 51820
target = 203.0.113.10:2083
key = testkey
masking = STUN
verbose = INFO
idle-timeout = 300
max-dummy = 4
# pca-tcp = 443
"""
let link = "phobos://" + Data(conf.utf8).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "") + "#demo"
let (p, name) = PhobosProfile.fromLink(link)!
precondition(name == "demo" && p.targetHost == "203.0.113.10" && p.targetPort == 2083 && p.tcpPort == 443)
let obf = p.obfuscatorConfig(listen: 13255, target: "127.0.0.1:13258")
precondition(obf.contains("target = 127.0.0.1:13258") && obf.contains("key = testkey") && !obf.contains("203.0.113.10"))
let wg = p.wireGuardConfig(endpoint: "127.0.0.1:13255", allowedIPs: "1.0.0.0/8")
precondition(wg.contains("Endpoint = 127.0.0.1:13255") && wg.contains("AllowedIPs = 1.0.0.0/8") && !wg.contains("= none"))
precondition(wg.contains("MTU = 1280") && !wg.contains("1420"))  // panel default -> 1280
let custom = PhobosProfile.fromLink("phobos://" + Data(conf.replacingOccurrences(of: "MTU = 1420", with: "MTU = 1300").utf8).base64EncodedString())!.0
precondition(custom.wireGuardConfig(endpoint: "e", allowedIPs: nil).contains("MTU = 1300"))  // link MTU wins
print("profile_check ok")
