#!/system/bin/sh
MODDIR=${0%/*}
APK_PATH="$MODDIR/xgj.apk"
LOG_FILE="/data/local/tmp/magisk_xgj.log"
PACKAGE_NAME="com.xiaojia.xgj"

export PATH=/system/bin:/system/xbin:$PATH

log() {
    echo "[Magisk Module] $1" >> "$LOG_FILE"
}

# 1. 清空旧日志
> "$LOG_FILE"

[ "$(id -u)" -eq 0 ] || exit 1

# 2. 检查 APK
if [ ! -f "$APK_PATH" ]; then
    log "ERROR: APK not found at $APK_PATH"
    exit 1
fi

# 3. 等待系统启动完成
log "Waiting for boot_completed..."
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done
sleep 5

# 4. 确保 pm 可用
log "Waiting for pm service..."
while ! pm list packages >/dev/null 2>&1; do
    sleep 1
done

SDK_VERSION=$(getprop ro.build.version.sdk)
log "Detected SDK_VERSION=$SDK_VERSION"

if [ "$SDK_VERSION" -ge 29 ]; then
    log "→ Using split-install flow"

    # 创建 session
    CREATE_OUT=$(pm install-create -r) 
    SESSION_ID=$(echo "$CREATE_OUT" | sed -n 's/.*\[\([0-9]\+\)\].*/\1/p')
    log "Session created: $SESSION_ID"

    if [ -z "$SESSION_ID" ]; then
        log "Failed to parse session ID, fallback to pm install -r"
        pm install -r "$APK_PATH" >> "$LOG_FILE" 2>&1
        exit $?
    fi

    # 计算 APK 大小（字节数）
    APK_SIZE=$(stat -c '%s' "$APK_PATH" 2>/dev/null || echo 0)
    log "APK size: $APK_SIZE bytes"

    # 写入 split "base.apk"
    pm install-write -S "$APK_SIZE" "$SESSION_ID" base.apk "$APK_PATH" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        log "pm install-write failed, fallback to pm install -r"
        pm install -r "$APK_PATH" >> "$LOG_FILE" 2>&1
        exit $?
    fi

    # 提交安装
    pm install-commit "$SESSION_ID" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        log "pm install-commit failed"
        exit 1
    fi

    log "APK installed via session $SESSION_ID"

else
    log "→ Using single-install flow"
    pm install -r "$APK_PATH" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        log "pm install -r failed"
        exit 1
    fi
    log "APK installed via pm install -r"
fi


# inotifywait -m -e delete_self $MODDIR --format "%e" | while read event
# do
#     if [ "$event" == "DELETE_SELF" ]; then
#         log "模組被刪除，準備卸載 $PACKAGE_NAME"
#         pm uninstall "$PACKAGE_NAME" >> $LOG_FILE 2>&1
#         if [ $? -eq 0 ]; then
#             log "$PACKAGE_NAME 卸載成功"
#         else
#             log "$PACKAGE_NAME 卸載失敗"
#         fi
#         exit 0
#     fi
# done

# 脚本完成
exit 0
