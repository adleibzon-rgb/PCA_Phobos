#!/usr/bin/env bash
# Build PCA Phobos Android app without Gradle: aapt2 -> javac -> d8 -> zipalign -> apksigner.
#   ANDROID_HOME=~/Library/Android/sdk KS=~/.android/pca-phobos.jks KS_PASS=… ./build.sh
# Output: build/PCA-Phobos.apk. The keystore is NOT in git (keep the same one, or updates won't install).
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/$(ls "$SDK/build-tools" | sort -V | tail -1)"
JAR="$SDK/platforms/$(ls "$SDK/platforms" | sort -V | tail -1)/android.jar"
KS="${KS:-$HOME/.android/pca-phobos.jks}"
KS_PASS="${KS_PASS:?set KS_PASS (keystore password)}"
rm -rf build && mkdir -p build/res build/classes build/dex

"$BT/aapt2" compile --dir res -o build/res/
"$BT/aapt2" link -o build/base.apk -I "$JAR" --manifest AndroidManifest.xml \
    --java build/gen build/res/*.flat --min-sdk-version 23 --target-sdk-version 35
javac -source 11 -target 11 -nowarn -classpath "$JAR" -d build/classes \
    $(find src build/gen -name '*.java') 2>&1 | grep -v "bootstrap classpath" || true
"$BT/d8" --release --lib "$JAR" --min-api 23 --output build/dex $(find build/classes -name '*.class')
cp build/base.apk build/unsigned.apk
(cd build/dex && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -alias pca -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=PCA Phobos, O=PCAdministration" >/dev/null
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --out build/PCA-Phobos.apk build/aligned.apk
"$BT/apksigner" verify build/PCA-Phobos.apk && ls -la build/PCA-Phobos.apk
