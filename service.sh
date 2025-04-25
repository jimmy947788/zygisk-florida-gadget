#!/system/bin/sh
MODDIR=${0%/*}
MODULE_ID=$(basename "$MODDIR")
LOG_FILE="/data/local/tmp/magisk_xgj.log"

# 确保路径定义
export PATH=/system/bin:/system/xbin:$PATH

# 定义日志函数
log() {
    echo "[Magisk Module] $1" >> $LOG_FILE
}

[ "$(id -u)" -eq 0 ] || exit 1

# APK 文件路径
APK_PATH="$MODDIR/xgj.apk"
PACKAGE_NAME="com.xiaojia.xgj"

# 检查 APK 是否存在
if [ ! -f "$APK_PATH" ]; then
    log "APK 文件不存在: $APK_PATH"
    exit 1
fi

# 等待系统完全启动
log "等待系统启动完成"
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done
sleep 5 # 额外等待，确保服务启动完成

# 检查 pm 是否可用
log "检查 pm 命令状态"
while ! pm list packages >/dev/null 2>&1; do
    sleep 1
done

# 获取系统版本
SDK_VERSION=$(getprop ro.build.version.sdk)
log "检测到系统版本: $SDK_VERSION"

# 根据系统版本选择安装方法
if [ "$SDK_VERSION" -ge 29 ]; then
    # 高版本安裝邏輯
    log "使用高版本安装逻辑"
    {
        INSTALL_CREATE_OUTPUT=$(pm install-create -r)
        INSTALL_SESSION=$(echo "$INSTALL_CREATE_OUTPUT" | awk -F'[][]' '{print $2}')

        log "安装会话创建成功: $INSTALL_SESSION"

        if [ -z "$INSTALL_SESSION" ]; then
            log "未能成功解析 session ID，切換至低版本安裝方式"
            pm install -r "$APK_PATH" >> $LOG_FILE 2>&1
            exit 1
        fi

        pm install-write "$INSTALL_SESSION" 0 "$APK_PATH" "$APK_PATH"
        if [ $? -ne 0 ]; then
            log "写入 APK 文件失败"
            log "降级，使用低版本安装逻辑"
            pm install -r "$APK_PATH" >> $LOG_FILE 2>&1
            if [ $? -ne 0 ]; then
                log "APK 安装失败"
                exit 1
            fi
            log "APK 安装完成"
            exit 1
        fi

        pm install-commit "$INSTALL_SESSION"
        if [ $? -ne 0 ]; then
            log "提交安装会话失败"
            exit 1
        fi
        log "APK 安装完成"
    } >> $LOG_FILE 2>&1
else
    # 低版本 Android（SDK < 29）
    log "使用低版本安装逻辑"
    pm install -r "$APK_PATH" >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
        log "APK 安装失败"
        exit 1
    fi
    log "APK 安装完成"
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
