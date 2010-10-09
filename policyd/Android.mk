LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= policyd.c
LOCAL_MODULE := policyd
LOCAL_STATIC_LIBRARIES := liblog
include $(BUILD_EXECUTABLE)
