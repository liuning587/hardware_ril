# Copyright 2006 The Android Open Source Project

# XXX using libutils for simulator build only...
#
ifneq ($(BOARD_MODEM_VENDOR), MC9090)
LOCAL_PATH:= $(call my-dir)
$(shell touch $(LOCAL_PATH)/*)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    reference-ril.c \
    atchannel.c \
    misc.c \
    at_tok.c \
    ql-pppd.c \
    ql-ndis.c

LOCAL_SHARED_LIBRARIES := \
    libcutils libutils libril

# for asprinf
LOCAL_CFLAGS := -D_GNU_SOURCE

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

ifeq ($(TARGET_DEVICE),sooner)
  LOCAL_CFLAGS += -DOMAP_CSMI_POWER_CONTROL -DUSE_TI_COMMANDS
endif

ifeq ($(TARGET_DEVICE),surf)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

ifeq ($(TARGET_DEVICE),dream)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

LOCAL_CFLAGS += -Wno-unused-parameter

LOCAL_CFLAGS += -DMUX_ANDROID
LOCAL_SRC_FILES += gsm0710muxd_bp.c

ifeq (foo,foo)
  #build shared library
  LOCAL_SHARED_LIBRARIES += \
      libcutils libutils
  LOCAL_CFLAGS += -DRIL_SHLIB
  LOCAL_MODULE:= libreference-ril
  include $(BUILD_SHARED_LIBRARY)
else
  #build executable
  LOCAL_SHARED_LIBRARIES += \
      libril
  LOCAL_MODULE:= reference-ril
  include $(BUILD_EXECUTABLE)
endif

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= chat.c
LOCAL_CFLAGS += -Wno-unused-parameter -Wno-sign-compare
LOCAL_SHARED_LIBRARIES += libcutils libutils
LOCAL_MODULE_TAGS:=eng optional
LOCAL_MODULE:= chat
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= ip-up.c
LOCAL_SHARED_LIBRARIES += libcutils libutils
LOCAL_MODULE_TAGS:=eng optional
LOCAL_MODULE_PATH:= $(TARGET_OUT_ETC)/ppp
LOCAL_MODULE:= ip-up
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= ip-down.c
LOCAL_SHARED_LIBRARIES += libcutils libutils
LOCAL_MODULE_TAGS:=eng optional
LOCAL_MODULE_PATH:= $(TARGET_OUT_ETC)/ppp
LOCAL_MODULE:= ip-down
include $(BUILD_EXECUTABLE)
endif
