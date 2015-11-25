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
extern int ql_mux_enabled;

#define MAX_PATH 256
#define USBID_LEN 4
struct ql_usb_id_struct {
    unsigned short vid;
    unsigned short pid;
    unsigned short at_inf;
    unsigned short ppp_inf;
    
};
static const struct ql_usb_id_struct ql_usb_id_table[] = {
    {0x05c6, 0x9003, 2, 3}, //UC20
    {0x05c6, 0x9090, 2, 3}, //UC15
    {0x05c6, 0x9215, 2, 3}, //EC20
    {0x1519, 0x0331, 6, 0}, //UG95
    {0x1519, 0x0020, 6, 0}, //UG95
};
#define USB_AT_INF 0
#define USB_PPP_INF 1
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif
static int is_usb_match(unsigned short vid, unsigned short pid) {
    size_t i;
    for (i = 0; i < ARRAY_SIZE(ql_usb_id_table); i++) {
        if (vid == ql_usb_id_table[i].vid) {
            if (pid == 0x0000) //donot check pid
                return 1;
            else if (pid == ql_usb_id_table[i].pid)
                return 1;
        }
    }
    return 0;
}

static int idusb2hex(char idusbinfo[USBID_LEN]) {
    int i;
    int value = 0;
    for (i = 0; i < USBID_LEN; i++) {
        if (idusbinfo[i] < 'a')
            value |= ((idusbinfo[i] - '0') << ((3 - i)*4));
        else
             value |= ((idusbinfo[i] - 'a' + 10) << ((3 - i)*4));
    }
    return value;
}

static char * ql_get_ttyname(int usb_interface, char *out_ttyname) {
    struct dirent* ent = NULL;  
    DIR *pDir;  
    char dir[MAX_PATH], filename[MAX_PATH];
    struct stat statbuf;
    int idVendor = 0, idProduct = 0;
    int fd;
    int find_usb_device = 0;
    size_t i;

    out_ttyname[0] = '\0';
    dir[0] = '\0';
    strcat(dir, "/sys/bus/usb/devices");
    if ((pDir = opendir(dir)) == NULL)  {  
        LOGE("Cannot open directory:%s/", dir);  
        return NULL;  
    }  

    while ((ent = readdir(pDir)) != NULL)  {
        sprintf(filename, "%s/%s", dir, ent->d_name);  
        lstat(filename, &statbuf);
        if (S_ISLNK(statbuf.st_mode))  {
            char idusbinfo[USBID_LEN+1] = {0};
            
            idVendor = idProduct = 0x0000;
            sprintf(filename, "%s/%s/idVendor", dir, ent->d_name);
            fd = open(filename, O_RDONLY);
            if (fd > 0) {
                if (4 == read(fd, idusbinfo, USBID_LEN))
                    idVendor = idusb2hex(idusbinfo);
                close(fd);
            }
            if (!is_usb_match(idVendor, idProduct))
                continue;

            sprintf(filename, "%s/%s/idProduct", dir, ent->d_name);
            fd = open(filename, O_RDONLY);
            if (fd > 0) {
                if (4 == read(fd, idusbinfo, USBID_LEN))
                    idProduct = idusb2hex(idusbinfo);
                close(fd);
            }
            if (!is_usb_match(idVendor, idProduct))
                continue;
        
            LOGD("find vid=0x%04x, pid=0x%04x", idVendor, idProduct);
            find_usb_device = 1;
            break;
        }
    }
    closedir(pDir);

    for (i = 0; i < ARRAY_SIZE(ql_usb_id_table); i++) {
        if ((idVendor == ql_usb_id_table[i].vid) && (idProduct == ql_usb_id_table[i].pid)) {
            if (usb_interface == USB_AT_INF) {
                usb_interface = ql_usb_id_table[i].at_inf;
                break;
            } else if (usb_interface == USB_PPP_INF) {
                usb_interface = ql_usb_id_table[i].ppp_inf;
                break;
             }
        }
    }
    if (i == ARRAY_SIZE(ql_usb_id_table))
        return NULL;

    if (find_usb_device) {
        char usb_inf_path[20];
        sprintf(usb_inf_path, "/%s:1.%d", ent->d_name, usb_interface);
        strcat(dir, usb_inf_path);
        if ((pDir = opendir(dir)) == NULL)  {  
            LOGE("Cannot open directory:%s/", dir);  
            return NULL;
        }
                       
        while ((ent = readdir(pDir)) != NULL)  {
            if (strncmp(ent->d_name, "tty", 3) == 0) {
                LOGD("find vid=0x%04x, pid=0x%04x, tty=%s", idVendor, idProduct, ent->d_name);
                strcpy(out_ttyname, ent->d_name);
            break;
            } 
        }
        closedir(pDir); 
    }

    if (strcmp(out_ttyname, "tty") == 0) { //find tty not ttyUSBx or ttyACMx
        strcat(dir, "/tty");
        if ((pDir = opendir(dir)) == NULL)  {  
            LOGE("Cannot open directory:%s/", dir);  
            return NULL;
        }
        
        while ((ent = readdir(pDir)) != NULL)  {
            if (strncmp(ent->d_name, "tty", 3) == 0) {
                LOGD("find vid=0x%04x, pid=0x%04x, tty=%s", idVendor, idProduct, ent->d_name);
                strcpy(out_ttyname, ent->d_name);
                break;
            } 
        }
        closedir(pDir); 
    }

    if (out_ttyname[0])
        return out_ttyname;
    return NULL;
}

char * ql_get_ttyAT(char *out_ttyname) {
    if(!ql_get_ttyname(USB_AT_INF, out_ttyname)) {
        LOGE("cannot find ttyname for AT Port");
        return NULL;
    }
    return out_ttyname;
}

char *  ql_get_ttyPPP(char *out_ttyname) {
    if(!ql_get_ttyname(USB_PPP_INF, out_ttyname)) {
        LOGE("cannot find ttyname for PPP Port");
        return NULL;
    }
    return out_ttyname;
}

static int chat(int fd, const char *at, const char *expect, int timeout, char **response) {
    int ret;
    static char buf[128];

    if (response)
        *response = NULL;

    tcflush(fd, TCIOFLUSH);
    LOGD("chat --> %s", at);
    do {
        ret = write(fd, at, strlen(at));
    } while (ret < 0 && errno == EINTR);
    
    if (ret <= 0) {
        LOGD("chat write error on stdout: %s(%d) ", strerror(errno), errno);
        return errno ? errno : EINVAL;
    }

    while(timeout > 0) {
        struct pollfd poll_fd = {fd, POLLIN, 0};
        if(poll(&poll_fd, 1, 200) <= 0) {
            if (errno == ETIMEDOUT) {
                timeout -= 200;
                continue;
            } else if(errno != EINTR) {
                LOGE("chat poll error on stdin: %s(%d) ", strerror(errno), errno);
                return errno ? errno : EINVAL;
            }
        }
        
        if(poll_fd.revents && (poll_fd.revents & POLLIN)) {
            memset(buf, 0, sizeof(buf));
            usleep(100*1000);
            if(read(fd, buf, sizeof(buf)-1) <= 0) {
                LOGD("chat read error on stdin: %s(%d) ", strerror(errno), errno);
                return errno ? errno : EINVAL;
            }
            LOGD("chat %d <-- %s", strlen(buf), buf);  
            if(strstr(buf, expect)) {
                if (response)
                    *response = strstr(buf, expect);
                return 0;
            }
        }    
    }

    return errno ? errno : EINVAL;
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

static int ql_pppd(const char *modemport, const char *user, const char *password, const char *auth_type) {
    char ttyname[10];
    char serialdevname[20];
    pid_t child_pid;
    int modem_fd, fdflags;
    struct termios  ios;
    int modembits = TIOCM_DTR;
    char *response;
      
__ql_pppd_restart:
    while (!modemport && !ql_get_ttyPPP(ttyname)) {
        sleep(3);
    }

    if (!modemport) {
        strcpy(serialdevname, "/dev/");
        strcat(serialdevname, ttyname);
    } else {
        strcpy(serialdevname, modemport);
    }

    //make sure modem is not in data mode!
    modem_fd = open (serialdevname, O_RDWR | O_NONBLOCK);
    if (modem_fd == -1) {
        LOGE("failed to open %s  errno: %d (%s)\n",  serialdevname, errno, strerror(errno));
        sleep(3);
        goto __ql_pppd_restart;  
     }
    fdflags = fcntl(modem_fd, F_GETFL);
    if (fdflags != -1)
        fcntl(modem_fd, F_SETFL, fdflags | O_NONBLOCK);
    /* disable echo on serial ports */
    tcgetattr( modem_fd, &ios );
    cfmakeraw(&ios);
    ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
    cfsetispeed(&ios, B115200);
    cfsetospeed(&ios, B115200);
    tcsetattr( modem_fd, TCSANOW, &ios );

    ioctl(modem_fd, (0 ? TIOCMBIS: TIOCMBIC), &modembits); //clear DTR
    if (chat(modem_fd, "AT\r", "OK", 1000, NULL)) {
        if (ql_mux_enabled) {
            close(modem_fd);
            sleep(3);
        } else {
            ioctl(modem_fd, (1 ? TIOCMBIS: TIOCMBIC), &modembits);
            sleep(1);
            ioctl(modem_fd, (0 ? TIOCMBIS: TIOCMBIC), &modembits);
            sleep(1);
            close(modem_fd);
        }
        goto __ql_pppd_restart;  
    }  

    chat(modem_fd, "AT+CGREG?\r", "+CGREG: ", 1000, &response);
    if (response)
        response = strstr(response, ",");
    if (!response || ((response[1] != '1') && (response[1] != '5'))) {
        close(modem_fd);
        sleep(3);
        goto __ql_pppd_restart;        
    }
    if (ql_mux_enabled) {
        //close(modem_fd);
        //sleep(1);
    } else {
        close(modem_fd);  
    }

    child_pid = fork();
    if (0 == child_pid) { //this is the child_process
        int argc = 0;

        const char *argv[40] = {"pppd", "115200", "nodetach", "nolock", "debug", "dump", "nocrtscts", "modem", "hide-password", 
            "usepeerdns", "noipdefault", "novj", "novjccomp", "noccp", "defaultroute", "ipcp-accept-local", "ipcp-accept-remote", "ipcp-max-failure", "10",
            //"connect", "/etc/ppp/init.quectel-pppd chat connect",
            //"disconnect","/etc/ppp/init.quectel-pppd chat disconnect",
            NULL
        };
    
        while (argv[argc]) argc++;
        argv[argc++] = serialdevname;
        if (user && user[0] && password && password[0] && auth_type && auth_type[0] && (auth_type[0] != '0')) {
            argv[argc++] = "user";
            argv[argc++] = user;
            argv[argc++] = "password";
            argv[argc++] = password;            
            if (auth_type[0] == '0') { //  0 => PAP and CHAP is never performed.
                argv[argc++] = "refuse-pap";
                argv[argc++] = "refuse-chap";
            } else if (auth_type[0] == '1') { //  1 => PAP may be performed; CHAP is never performed.
                argv[argc++] = "refuse-chap";
            } else if (auth_type[0] == '2') { //  2 => CHAP may be performed; PAP is never performed.
                argv[argc++] = "refuse-pap";
            } else if (auth_type[0] == '3') { //  3 => PAP / CHAP may be performed - baseband dependent.
            }
            argv[argc++] = "refuse-eap";
            argv[argc++] = "refuse-mschap";
            argv[argc++] = "refuse-mschap-v2";
        }

        if (access("/system/bin/pppd", X_OK)) {
            LOGE("/system/bin/pppd do not exist or is not Execute!");
            exit(ENOENT);
        }        
        if (access("/system/bin/chat", X_OK)) {
            LOGE("/system/bin/chat do not exist or is not Execute!");
            exit(ENOENT);
        }
        if (access("/etc/ppp/ip-up", X_OK)) {
            LOGE("/etc/ppp/ip-up do not exist or is not Execute!");
            exit(ENOENT);
        }
        argv[argc++] = "connect";
        argv[argc++] = "''/system/bin/chat -s -v ABORT BUSY ABORT \"NO CARRIER\" ABORT \"NO DIALTONE\" ABORT ERROR ABORT \"NO ANSWER\" TIMEOUT 12 \"\" ATD*99# CONNECT''";        
        argv[argc++] = NULL;

        if (execv("/system/bin/pppd", (char**) argv)) {
            LOGE("cannot execve('%s'): %s\n", argv[0], strerror(errno));
            exit(errno);
        }
        exit(0);
    } else if (child_pid < 0) {
        LOGE("failed to start ('%s'): %s\n", "pppd", strerror(errno));
        return errno;
    } else {
        int status, retval = 0;     
        waitpid(child_pid, &status, 0);
        if (ql_mux_enabled)
            close(modem_fd);
        if (WIFSIGNALED(status)) {
            retval = WTERMSIG(status);
            LOGD("*** %s: Killed by signal %d retval = %d\n", "pppd", WTERMSIG(status), retval);
        } else if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
            retval = WEXITSTATUS(status);
            LOGD("*** %s: Exit code %d retval = %d\n", "pppd", WEXITSTATUS(status), retval);
        }  
        sleep(3);
        goto __ql_pppd_restart;
    }

    return 0;     
}

int ql_pppd_stop(int signo);
static pid_t ql_pppd_pid = 0;
int ql_pppd_start(const char *modemport, const char *user, const char *password, const char *auth_type) {
    ql_pppd_stop(SIGKILL);
    ql_pppd_pid = fork();
    if (ql_pppd_pid == 0) {
        ql_pppd(modemport, user, password, auth_type);
        exit(0);
    } else if (ql_pppd_pid < 0) {
        LOGE("failed to start ('%s'): %s\n", "ql-pppd", strerror(errno));
    }
    //LOGD("ql_pppd_pid = %d", ql_pppd_pid);
    return ql_pppd_pid;
}

void ql_kill_pppd(int signo) {
    int child_pid = 0;
    pid_t pppd_pid = ql_get_pid("/system/bin/pppd");
    if (pppd_pid <= 0)
        return;

    child_pid = fork();
    if (child_pid == 0) {//kill may take long time, so do it in child process
        int pppd_kill_time = 10;
        ql_kill_pid(pppd_pid, signo);
        while(pppd_kill_time--&& !ql_kill_pid(pppd_pid, 0)) //wait pppd quit
            sleep(1);
        if ((signo != SIGKILL) && (pppd_kill_time < 0) && !ql_kill_pid(pppd_pid, 0))
            ql_kill_pid(pppd_pid, SIGKILL);
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

int ql_pppd_stop(int signo) {
    if (ql_pppd_pid > 0) {
        ql_kill_pid(ql_pppd_pid, SIGKILL);
        ql_pppd_pid = 0;
    }
    ql_kill_pppd(signo);
    return 0;
}
