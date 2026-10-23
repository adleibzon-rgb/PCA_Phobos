#!/bin/bash
# Install PCA Phobos for macOS from the staged folder (~/.pca-phobos). Run once:  sudo bash ~/.pca-phobos/install-mac.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
U="${SUDO_USER:?run via sudo from your account}"
S="$(eval echo "~$U")/.pca-phobos"
D=/usr/local/pca-phobos

install -d -m 755 -o root -g wheel "$D" "$D/bin"
install -m 755 -o root -g wheel "$S/bin/wg-obfuscator" "$S/bin/udptcp" "$D/bin/"
install -m 644 -o root -g wheel "$S/ru_bypass.txt" "$D/"
install -m 600 -o root -g wheel "$S/profile.conf" "$S/home.key" "$D/"
for f in home_pub home_endpoint home_addr; do install -m 644 -o root -g wheel "$S/$f" "$D/"; done
install -m 755 -o root -g wheel "$S/phobos" /usr/local/bin/phobos

# the menu bar app may run exactly this root-owned script without a password
echo "$U ALL=(root) NOPASSWD: /usr/local/bin/phobos" > /etc/sudoers.d/pca-phobos
chmod 440 /etc/sudoers.d/pca-phobos
visudo -cf /etc/sudoers.d/pca-phobos >/dev/null || { rm -f /etc/sudoers.d/pca-phobos; echo "sudoers check failed"; exit 1; }

rm -rf "/Applications/PCA Phobos.app"
cp -R "$S/PCAPhobos.app" "/Applications/PCA Phobos.app"
LA="$(eval echo "~$U")/Library/LaunchAgents/com.bobyrev.pcaphobos.mac.plist"
cat > "$LA" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.bobyrev.pcaphobos.mac</string>
<key>ProgramArguments</key><array><string>/Applications/PCA Phobos.app/Contents/MacOS/PCAPhobos</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
EOF
chown "$U" "$LA"
sudo -u "$U" launchctl bootstrap "gui/$(id -u "$U")" "$LA" 2>/dev/null || sudo -u "$U" open "/Applications/PCA Phobos.app"
echo "PCA Phobos installed: menu bar icon, or 'sudo phobos on|off|status'"
