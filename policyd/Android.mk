LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= policyd.c
LOCAL_MODULE := policyd
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_SHARED_LIBRARIES := libpolicydb
LOCAL_C_INCLUDES += \
    external/policydb
include $(BUILD_EXECUTABLE)
