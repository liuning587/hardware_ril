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

#define MAX_PATH 256
int ql_get_ndisname(char **pp_usbnet_adapter) {
    struct dirent* ent = NULL;  
    struct dirent* subent = NULL;  
    DIR *pDir, *pSubDir;  
    char dir[MAX_PATH], subdir[MAX_PATH];
    int fd;
    int find_usb_device = 0;
    int find_qmichannel = 0;

    *pp_usbnet_adapter = NULL;
    
    strcpy(dir, "/sys/bus/usb/devices");
    if ((pDir = opendir(dir)) == NULL)  {  
        LOGE("Cannot open directory: %s", dir);  
        return -ENODEV;  
    }  

    while ((ent = readdir(pDir)) != NULL) {
        char idVendor[5] = "";
        char idProduct[5] = "";
                  
        sprintf(subdir, "%s/%s/idVendor", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idVendor, 4);
            close(fd);
        //dbg_time("idVendor = %s\n", idVendor);
            if (strncasecmp(idVendor, "05c6", 4)) {
                continue;
            }
        } else {
            continue;
        }

        sprintf(subdir, "%s/%s/idProduct", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idProduct, 4);
            close(fd);
            //dbg_time("idProduct = %s\n", idProduct);
            if (strncasecmp(idProduct, "9003", 4) && strncasecmp(idProduct, "9215", 4)) {
                continue;
            }
        } else {
            continue;
        }
    
        LOGE("Find idVendor=%s, idProduct=%s", idVendor, idProduct);
        find_usb_device = 1;
        break;
    }
    closedir(pDir);

    if (!find_usb_device) {
        LOGE("Cannot find Quectel UC20/EC20");
        return -ENODEV;  
    }      

    sprintf(subdir, "/%s:1.%d", ent->d_name, 4);
    strcat(dir, subdir);
    if ((pDir = opendir(dir)) == NULL)  {  
        LOGE("Cannot open directory:%s/", dir);  
        return -ENODEV;  
    }
                       
    while ((ent = readdir(pDir)) != NULL) {
        //dbg_time("%s\n", ent->d_name);
        if (strncmp(ent->d_name, "usbmisc", strlen("usbmisc")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/usbmisc");
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0) {
                    LOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    break;
                }                         
            }
            closedir(pSubDir);
        } 

        else if (strncmp(ent->d_name, "GobiQMI", strlen("GobiQMI")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/GobiQMI");
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "qcqmi", strlen("qcqmi")) == 0) {
                    LOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    break;
                }                         
            }
            closedir(pSubDir);
        }         

        else if (strncmp(ent->d_name, "net", strlen("net")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/net");
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if ((strncmp(subent->d_name, "wwan", strlen("wwan")) == 0)
                    || (strncmp(subent->d_name, "eth", strlen("eth")) == 0)
                    || (strncmp(subent->d_name, "usb", strlen("usb")) == 0)) {
                    *pp_usbnet_adapter = strdup(subent->d_name);
                    LOGD("Find usbnet_adapter = %s", *pp_usbnet_adapter );
                    break;
                }                         
            }
            closedir(pSubDir);
        } 

        if (find_qmichannel && *pp_usbnet_adapter)
            break;
    }
    closedir(pDir);     

    return (find_qmichannel && *pp_usbnet_adapter) ? 0 : -1;
}

static int ql_kill_pid(pid_t pid, int signo) {
    int ret = kill(pid, signo);
    //LOGD("%s(%d, %d) = %d\n", __func__, pid, signo, ret);
    return ret;
}

static pid_t ql_get_pid(const char *pname) {
    DIR *pDir;  
    struct dirent* ent = NULL;
    pid_t pid = 0;
    char *linkname = (char *) malloc (MAX_PATH + MAX_PATH);
    char *filename = linkname + MAX_PATH;
    int filenamesize;

    if (!linkname)
        return 0;

    pDir = opendir("/proc");
    if (pDir == NULL)  {  
        LOGE("Cannot open directory: /proc, errno: %d (%s)", errno, strerror(errno));  
        return 0;  
    }  

    while ((ent = readdir(pDir)) != NULL)  {
        int i = 0;
        //LOGD("%s", ent->d_name);
        while (ent->d_name[i]) {
            if ((ent->d_name[i] < '0')  || (ent->d_name[i] > '9'))
                break;
            i++;
         }

        if (ent->d_name[i]) {
            //LOGD("%s not digit", ent->d_name);           
            continue;
        }

        sprintf(linkname, "/proc/%s/exe", ent->d_name);  
        filenamesize = readlink(linkname, filename, MAX_PATH-1);
        if (filenamesize > 0) {
            filename[filenamesize] = 0;
            if (!strcmp(filename, pname)) {
                pid = atoi(ent->d_name);
                LOGD("%s -> %s", linkname, filename);
            }
        } else {
            //LOGD("readlink errno: %d (%s)", errno, strerror(errno));
        }
    }
    closedir(pDir);
    free(linkname);

    return pid;
}

static int ql_ndis_daemon(const char *apn, const char *user, const char *password, const char *auth_type) {   
    pid_t child_pid;

____ql_ndis_restart:
    child_pid = fork();
    if (child_pid == 0) {
        const char *argv[10];
        int argc = 0;
        argv[argc++] = "quectel-CM";
        argv[argc++] = "-s";
        if (apn && apn[0])
            argv[argc++] = apn;
        else
             argv[argc++] = "\"\"";
        if (user && user[0])
            argv[argc++] = user;
        else
            argv[argc++] = "\"\"";
        if (password && password[0])
            argv[argc++] = password;
        else
            argv[argc++] = "\"\"";
        if (auth_type && auth_type[0])
            argv[argc++] = auth_type;
        else
            argv[argc++] = "\"\"";
        argv[argc++] = NULL;

        if (execv("/system/bin/quectel-CM", (char**) argv)) {
            LOGE("cannot execve('%s'): %s\n", argv[0], strerror(errno));
            exit(errno);
        }
        exit(0);
    } else if (child_pid < 0) {
        LOGE("failed to start ('%s'): %s\n", "quectel-CM", strerror(errno));
        return errno;
    } else {
        int status, retval = 0;     
        waitpid(child_pid, &status, 0);
        if (WIFSIGNALED(status)) {
            retval = WTERMSIG(status);
            LOGD("*** %s: Killed by signal %d retval = %d\n", "quectel-CM", WTERMSIG(status), retval);
        } else if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
            retval = WEXITSTATUS(status);
            LOGD("*** %s: Exit code %d retval = %d\n", "quectel-CM", WEXITSTATUS(status), retval);
        }  
        sleep(3);
        goto ____ql_ndis_restart;
    }

    return 0;     
}

int ql_ndis_stop(int signo);
static pid_t ql_ndis_pid = 0;
int ql_ndis_start(const char *apn, const char *user, const char *password, const char *auth_type) {
    if (access("/system/bin/quectel-CM", X_OK))
        return -ENODEV;
    
    ql_ndis_stop(SIGKILL);
    ql_ndis_pid = fork();
    if (ql_ndis_pid == 0) {
        ql_ndis_daemon(apn, user, password, auth_type);
        exit(0);
    } else if (ql_ndis_pid < 0) {
        LOGE("failed to start ('%s'): %s\n", "quectel-CM", strerror(errno));
    }
    //LOGD("ql_pppd_pid = %d", ql_pppd_pid);
    return ql_ndis_pid;
}

void ql_kill_ndis(int signo) {
    int child_pid = 0;
    pid_t ndis_pid;

    if (access("/system/bin/quectel-CM", X_OK))
        return;

    ndis_pid = ql_get_pid("/system/bin/quectel-CM");
    if (ndis_pid <= 0)
        return;

    child_pid = fork();
    if (child_pid == 0) {//kill may take long time, so do it in child process
        int pppd_kill_time = 10;
        ql_kill_pid(ndis_pid, signo);
        while(pppd_kill_time--&& !ql_kill_pid(ndis_pid, 0)) //wait pppd quit
            sleep(1);
        if ((signo != SIGKILL) && (pppd_kill_time < 0) && !ql_kill_pid(ndis_pid, 0))
            ql_kill_pid(ndis_pid, SIGKILL);
        exit(0);
    } else if (child_pid > 0) {
        if (signo == SIGTERM) {
            int pppd_kill_time = 10;
            do {
                sleep(1);
            } while(pppd_kill_time-- && !waitpid(child_pid, NULL, WNOHANG));
            LOGD("%s cost %d secs", __func__, (10-pppd_kill_time));
            //sleep(1); //leave enough time between close and reopen /dev/chn/2, required by CMUX
        }
    }
}

int ql_ndis_stop(int signo) {
    if (access("/system/bin/quectel-CM", X_OK))
        return -ENODEV;

    if (ql_ndis_pid > 0) {
        ql_kill_pid(ql_ndis_pid, SIGKILL);
        ql_ndis_pid = 0;
    }
    ql_kill_ndis(signo);
    return 0;
}
