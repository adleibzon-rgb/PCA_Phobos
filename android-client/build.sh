#!/usr/bin/env bash
# Build PCA Phobos VPN (client) without Gradle. Needs libs/: tunnel-*.aar (com.wireguard.android:tunnel),
# collection-*.jar, annotation-*.jar; jni/<abi>/libwgobfuscator.so (static ClusterM wg-obfuscator).
#   KS_PASS=… ./build.sh   -> build/PCA-Phobos-VPN.apk
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/$(ls "$SDK/build-tools" | sort -V | tail -1)"
JAR="$SDK/platforms/$(ls "$SDK/platforms" | sort -V | tail -1)/android.jar"
KS="${KS:-$HOME/.android/pca-phobos.jks}"
KS_PASS="${KS_PASS:?set KS_PASS}"
AAR=$(ls libs/tunnel-*.aar | tail -1)
rm -rf build && mkdir -p build/res build/classes build/dex build/aar build/apk/lib
unzip -q "$AAR" -d build/aar
LIBS="build/aar/classes.jar:$(ls libs/*.jar | tr '\n' ':')"
"$BT/aapt2" compile --dir res -o build/res/
"$BT/aapt2" link -o build/base.apk -I "$JAR" --manifest AndroidManifest.xml -A assets \
    --java build/gen build/res/*.flat --min-sdk-version 24 --target-sdk-version 35
javac -source 11 -target 11 -nowarn -classpath "$JAR:$LIBS" -d build/classes \
    $(find src build/gen -name '*.java') 2>&1 | grep -v "bootstrap classpath\|^Note:" || true
"$BT/d8" --release --lib "$JAR" --min-api 24 --output build/dex \
    $(find build/classes -name '*.class') build/aar/classes.jar libs/*.jar
cp build/base.apk build/unsigned.apk
(cd build/dex && zip -q ../unsigned.apk classes*.dex)
for abi in arm64-v8a armeabi-v7a; do
    mkdir -p "build/apk/lib/$abi"
    cp build/aar/jni/$abi/*.so "build/apk/lib/$abi/"
    cp "jni/$abi/libwgobfuscator.so" "build/apk/lib/$abi/"
done
(cd build/apk && zip -qr ../unsigned.apk lib)
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --out build/PCA-Phobos-VPN.apk build/aligned.apk
"$BT/apksigner" verify build/PCA-Phobos-VPN.apk && ls -la build/PCA-Phobos-VPN.apk
