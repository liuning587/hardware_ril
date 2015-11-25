#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <termios.h>

#define LOG_TAG "RIL"
#include <utils/Log.h>
#include <cutils/properties.h>

#if 1 //quectel PLATFORM_VERSION >= "4.2.2"
#ifndef LOGD
#define LOGD ALOGD
#endif
#ifndef LOGE
#define LOGE ALOGE
#endif
#ifndef LOGI
#define LOGI ALOGI
#endif
#endif

int main(int argc, char *argv[]) {
    argc = argc;
    argv = argv;  
    property_set("net.ppp0.dns1", "");
    property_set("net.ppp0.dns2", "");
    property_set("net.ppp0.local-ip", "");
    property_set("net.ppp0.remote-ip", "");
    property_set("net.ppp0.gw", "");
    return 0;
}
