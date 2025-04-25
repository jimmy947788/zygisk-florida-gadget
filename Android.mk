LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := zygisk-florida-gadget

# 你的主要程式碼
LOCAL_SRC_FILES := \
    $(LOCAL_PATH)/src/main.cpp \
    $(LOCAL_PATH)/src/gadget.cpp

# 加上 xdl 的所有 .c 檔
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/src/xdl/*.c)

# Include path
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(LOCAL_PATH)/src/xdl/include

LOCAL_STATIC_LIBRARIES := libcxx

LOCAL_LDLIBS := -llog
# LOCAL_CPPFLAGS := -std=c++17 -Wall -Werror
# LOCAL_CFLAGS := -Wall -Werror

include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/src/libcxx/Android.mk
