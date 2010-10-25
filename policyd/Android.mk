LOCAL_PATH:= $(call my-dir)

# policyd: policy server standalone executable
include $(CLEAR_VARS)
LOCAL_SRC_FILES:= policyd.c  policy_global.c
LOCAL_MODULE := policyd
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_SHARED_LIBRARIES := libpolicydb
LOCAL_C_INCLUDES += external/policydb system/core/include/cutils
include $(BUILD_EXECUTABLE)

# policy_client: used by dalvik VM to connect to policyd server
include $(CLEAR_VARS)
LOCAL_SRC_FILES:= policy_client.c  policy_global.c
LOCAL_MODULE:= libpolicy_client
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_C_INCLUDES += system/core/include/cutils
include $(BUILD_SHARED_LIBRARY)
