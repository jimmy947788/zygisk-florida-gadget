#!/bin/bash
set -e

# 模組資訊
MODULE_NAME=zygisk-florida-gadget
SO_NAME=lib$MODULE_NAME.so
MODULE_DIR=zygisk-florida-gadget
OUT_DIR=out/arm64-v8a
ABI=arm64-v8a

# gadget / apk 來源路徑（放在專案根目錄）
GADGET_DIR=gadget
GADGET_SRC=ajeossida-gadget-16.7.14-android-arm64.so
GADGET_SO=libgadget.so
GADGET_CONFIG_SO=libgadget.config.so
APK_FILE=xgj.apk
SERVICE_SCRIPT=service.sh

# 模組版本
MODULE_VERSION=16.7.14
MODULE_VERSION_CODE=100

# 若為 install 模式，直接 adb push zip
if [[ "$1" == "install" ]]; then
    echo "[*] Pushing $MODULE_NAME.zip to /sdcard/Download/ via ADB..."
    adb push build/$MODULE_NAME.zip /sdcard/Download/
    echo "[+] Push complete."
    exit 0
fi

if [[ "$1" == "clean" ]]; then
    echo "[*] Cleaning previous builds..."
    rm -rf $OUT_DIR build/ #module.prop $MODULE_NAME.zip
    exit 0
fi

# 檢查 NDK
if [ -z "$ANDROID_NDK" ]; then
    echo "[!] ANDROID_NDK 環境變數未設定"
    exit 1
fi

NDK_BUILD=$ANDROID_NDK/ndk-build
if [ ! -f "$NDK_BUILD" ]; then
    echo "[!] 找不到 ndk-build: $NDK_BUILD"
    exit 1
fi

# sudo apt-get install ccache
export NDK_CCACHE=$(which ccache)
echo "[*] NDK_CCACHE: $NDK_CCACHE"

# 清除與編譯
echo "[*] Cleaning previous builds..."
rm -rf $OUT_DIR zygisk module.prop $MODULE_NAME.zip
mkdir -p $OUT_DIR/libs/$ABI

echo "[*] Building .so..."
$NDK_BUILD -j$(nproc) \
    NDK_PROJECT_PATH=. \
    APP_BUILD_SCRIPT=Android.mk \
    NDK_APPLICATION_MK=Application.mk \
    APP_ABI=$ABI \
    NDK_OUT=$OUT_DIR/obj \
    NDK_LIBS_OUT=$OUT_DIR/libs

# 準備打包檔案
echo "[*] Preparing Zygisk module structure..."
mkdir -p build
mkdir -p build/zygisk
cp $OUT_DIR/libs/$ABI/$SO_NAME build/zygisk/$ABI.so

# 建立 module.prop
cat > build/module.prop <<EOF
id=$MODULE_NAME
name=Zygisk Florida Gadget
version=$MODULE_VERSION.$MODULE_VERSION_CODE
versionCode=$MODULE_VERSION_CODE
author=Jimmy
description=A zygisk hook module with direct-root gadget.
EOF


# 複製 gadget.so、config.so、apk、sh
cp $GADGET_DIR/$GADGET_SRC     build/$GADGET_SO
cp $GADGET_DIR/*.config build/$GADGET_CONFIG_SO
cp $APK_FILE            build/
cp $SERVICE_SCRIPT      build/
cp -r META-INF/         build/ 

# 打包進 zip：放根目錄的 gadget.so、config.so、apk、sh
echo "[*] Creating Magisk Zygisk module zip..."
cd build
zip -r $MODULE_NAME.zip \
    META-INF \
    zygisk \
    module.prop \
    $GADGET_SO \
    $GADGET_CONFIG_SO \
    $APK_FILE \
    $SERVICE_SCRIPT > /dev/null || true

echo "[+] Build and packaging complete: $MODULE_NAME.zip"
echo "[*] libgadget.so md5sum: $(md5sum $GADGET_SO | awk '{print $1}')"
# 顯示內容列表
echo "[*] ZIP 包內容："
unzip -l $MODULE_NAME.zip
