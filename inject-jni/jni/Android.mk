LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := my_inject 
LOCAL_SRC_FILES := my_inject.c 

#shellcode.s

LOCAL_LDLIBS += -L$(SYSROOT)/user/lib64 -llog

#LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)
