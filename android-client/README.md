# PCA Phobos VPN — Android-клиент

Своё приложение-клиент: импорт `phobos://` из панели, встроенный wg-obfuscator + WireGuard,
**раздельный трафик** по приложениям (весь / только выбранные / все кроме выбранных).

- WireGuard: `com.wireguard.android:tunnel` (Apache-2.0), `libs/`.
- Обфускатор: [ClusterM/wg-obfuscator](https://github.com/ClusterM/wg-obfuscator) v1.6 (GPL-3.0),
  собран NDK под bionic: `jni/<abi>/libwgobfuscator.so`. Статический glibc-бинарник с роутеров
  внутри приложения падает с SIGSYS (seccomp), поэтому только bionic-сборка.
- Само приложение всегда вне туннеля — иначе обфускатор не достучится до сервера.

Сборка без Gradle: `KS_PASS=… ./build.sh` → `build/PCA-Phobos-VPN.apk`
(ключ подписи — `~/.android/pca-phobos.jks`, пароль в ДОСТУПЫ.md; ключ не менять, иначе обновления не встанут).

Пересборка обфускатора:
```bash
NDK=~/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin
$NDK/aarch64-linux-android24-clang -O2 -std=gnu11 -o jni/arm64-v8a/libwgobfuscator.so wg-obfuscator/*.c
$NDK/armv7a-linux-androideabi24-clang -O2 -std=gnu11 -o jni/armeabi-v7a/libwgobfuscator.so wg-obfuscator/*.c
```
