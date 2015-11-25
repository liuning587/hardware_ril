/* //device/system/reference-ril/reference-ril.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include <getopt.h>
#include <linux/sockios.h>
#include <termios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/system_properties.h>
#if 1 //quectel
#include "../include/telephony/ril.h"
#include <cutils/properties.h>
#else

#include "ril.h"
#endif
#include "hardware/qemu_pipe.h"

#define LOG_TAG "RIL"
#include <utils/Log.h>

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

#define MAX_AT_RESPONSE 0x1000

#if 1 //quectel
/* pathname returned from RIL_REQUEST_SETUP_DATA_CALL / RIL_REQUEST_SETUP_DEFAULT_PDP */
//#define PPP_TTY_PATH "ppp0"
static const char *PPP_TTY_PATH = "ppp0";
#define CUSD_USE_UCS2_MODE
#define USB_HOST_SUSPEND_SUPPORT 1 //like s5pv210 donnot support usb suspend and wakeup
#define REFERENCE_RIL_VERSION    "Quectel_Android_RIL_SR01A34"
static  char ql_ttyAT[20];
extern char * ql_get_ttyAT(char *out_ttyname);
extern int ql_pppd_start(const char *modemport, const char *user, const char *password, const char *auth_type);
extern int ql_pppd_stop(int signo);
extern void ql_kill_pppd(int signo);
extern int ql_get_ndisname(char **pp_usbnet_adapter);
extern int ql_ndis_start(const char *modemport, const char *user, const char *password, const char *auth_type);
extern int ql_ndis_stop(int signo);
extern void ql_kill_ndis(int signo);
static const char *ql_product_version = NULL;
#define ql_is_XX(__ql_module_name) (!strncmp(ql_product_version, __ql_module_name, strlen(__ql_module_name)))
static int ql_is_UC20 = 0;
static int ql_is_EC20 = 0;
static int ql_is_UG95 = 0;
static int ql_is_GSM = 0;
#define NETWORK_DEBOUNCE_TIMEOUT 20
static int network_debounce_time = 0;
static int onRequestCount = 0;
static int time_zone_report = 0;
static const char* ql_nwscanmode = NULL;
static const char* ql_nwscanseq = NULL;
	
//#define QUECTEL_DEBUG
#ifdef QUECTEL_DEBUG //quectel //for debug-purpose, record logcat msg to file
//you can fetch logfiles to host-pc by adb tools using command "adb pull /data/ql_log/"
static void log_dmesg(const char *tag) {
#if 0 // may take long time
    if (fork() == 0) 
    {
        char logcat_cmd[100];
        void *pbuf;;
        size_t len;
        time_t rawtime;
        struct tm *timeinfo;
        FILE *dmesgfp, *logfilefp;
        time(&rawtime);
        timeinfo=localtime(&rawtime );
        sprintf(logcat_cmd, "/data/ql_log/%02d%02d_%02d%02d%02d_dmesg_%s.txt",
    		timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, tag);
        logfilefp = fopen(logcat_cmd, "wb");
        dmesgfp = popen("dmesg", "r");
        pbuf = malloc(8*1024);    
        if (logfilefp && dmesgfp && pbuf) {
            while((len = fread(pbuf, 1, 8*1024, dmesgfp)) > 0) {
                LOGD("%s len = %d\n", __func__, len);
                fwrite(pbuf, 1, len, logfilefp);
        	}
        } else {
            LOGD("logfilefp=%p, dmesgfp=%p, errno: %d (%s)", logfilefp, dmesgfp, errno, strerror(errno));
        }
        if (logfilefp)
            fclose(logfilefp);
        if (dmesgfp)
            fclose(dmesgfp);
        if (pbuf)
            free(pbuf);
        exit(0);
    }
#endif
}
#endif
static int gprsState = -1; // 1 ~in service, 0 ~ out of service
static void setDataServiceState(int newState) {
    newState = (newState != 0);
    if (newState != gprsState) {
        const char *gprsStateString[] = {"0", "1"};
        gprsState = newState;
        //property_set("net.gprs.gprsState", gprsStateString[gprsState]);
    }
}
static int currentDataServiceState(void) {
    return (gprsState == 1);
}

int ql_mux_enabled = 0;
#define CMUX_AT_PORT "/dev/chn/1" //"/dev/ttygsm1"
#define CMUX_PPP_PORT "/dev/chn/2" //"/dev/ttygsm2"
static int cmux_speed = 115200;
static int cmux_ctsrts = 0;
extern int gsm0710muxd(const char *serialname, int speed, int ctsrts);
//#undef RIL_VERSION
//static int RIL_VERSION = 6;
#endif

typedef enum {
    SIM_ABSENT = 0,
    SIM_NOT_READY = 1,
    SIM_READY = 2, /* SIM_READY means the radio state is RADIO_STATE_SIM_READY */
    SIM_PIN = 3,
    SIM_PUK = 4,
    SIM_NETWORK_PERSONALIZATION = 5
} SIM_Status;

static void onRequest (int request, void *data, size_t datalen, RIL_Token t);
static RIL_RadioState currentState();
static int onSupports (int requestCode);
static void onCancel (RIL_Token t);
static const char *getVersion();
static int isRadioOn();
static SIM_Status getSIMStatus();
static int getCardStatus(RIL_CardStatus_v6 **pp_card_status);
static void freeCardStatus(RIL_CardStatus_v6 *p_card_status);
static void onDataCallListChanged(void *param);

extern const char * requestToString(int request);

/*** Static Variables ***/
static const RIL_RadioFunctions s_callbacks = {
    RIL_VERSION,
    onRequest,
    currentState,
    onSupports,
    onCancel,
    getVersion
};

#ifdef RIL_SHLIB
static const struct RIL_Env *s_rilenv;

#define RIL_onRequestComplete(t, e, response, responselen) s_rilenv->OnRequestComplete(t,e, response, responselen)
#define RIL_onUnsolicitedResponse(a,b,c) s_rilenv->OnUnsolicitedResponse(a,b,c)
#define RIL_requestTimedCallback(a,b,c) s_rilenv->RequestTimedCallback(a,b,c)
#endif

static RIL_RadioState sState = RADIO_STATE_UNAVAILABLE;

static pthread_mutex_t s_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_state_cond = PTHREAD_COND_INITIALIZER;

static int s_port = -1;
static const char * s_device_path = NULL;
static int          s_device_socket = 0;

/* trigger change to this with s_state_cond */
static int s_closed = 0;

static int sFD;     /* file desc of AT channel */
static char sATBuffer[MAX_AT_RESPONSE+1];
static char *sATBufferCur = NULL;

static const struct timeval TIMEVAL_SIMPOLL = {1,0};
static const struct timeval TIMEVAL_CALLSTATEPOLL = {0,500000};
static const struct timeval TIMEVAL_0 = {0,0};

static void onSIMStateChange (void *param);
static void onSMSReady(void *param);
static void pollSIMState (void *param);
static void setRadioState(RIL_RadioState newState);

#if 1 //quectel
static unsigned int ussd_pending_index = 0;
static const struct timeval ussd_timeout_timeval = {30,0}; //seconds
static void onUssdResponse(char *mode) {
    char *response[2]; 
    response[0] = mode;
       
    switch (mode[0] - '0') {
        case 2:
            response[1] = "USSD terminated by network";
        break;
        case 3:
            response[1] = "Other local client has responded";
        break;
        case 4:
            response[1] = "Operation not supported";
        break;
        case 5:
        default:
            response[1] = "Network time out";
        break;      
    }
    RIL_onUnsolicitedResponse(RIL_UNSOL_ON_USSD, response, sizeof(response[0]) + sizeof(response[1]));
}
static void onUssdTimedCallback(void *param) {
    if (ussd_pending_index != ((unsigned int) param))
        return;
    at_send_command("AT+CUSD=2", NULL); //cancel
    onUssdResponse("5");
}

static int gsm_hexchar_to_int( char  c ) {
    if ((unsigned)(c - '0') < 10)
        return c - '0';
    if ((unsigned)(c - 'a') < 6)
        return 10 + (c - 'a');
    if ((unsigned)(c - 'A') < 6)
        return 10 + (c - 'A');
    return -1;
}

static int gsm_hex2_to_byte( const char*  hex ) {
    int  hi = gsm_hexchar_to_int(hex[0]);
    int  lo = gsm_hexchar_to_int(hex[1]);

    if (hi < 0 || lo < 0)
        return -1;

    return ( (hi << 4) | lo );
}

typedef unsigned char  byte_t;
typedef byte_t*        bytes_t;
typedef const byte_t*  cbytes_t;
static  int utf8_write( bytes_t  utf8, int  offset, int  v ) {
    int  result;

    if (v < 128) {
        result = 1;
        if (utf8)
            utf8[offset] = (byte_t) v;
    } else if (v < 0x800) {
        result = 2;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xc0 | (v >> 6) );
            utf8[offset+1] = (byte_t)( 0x80 | (v & 0x3f) );
        }
    } else if (v < 0x10000) {
        result = 3;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xe0 |  (v >> 12) );
            utf8[offset+1] = (byte_t)( 0x80 | ((v >> 6) & 0x3f) );
            utf8[offset+2] = (byte_t)( 0x80 |  (v & 0x3f) );
        }
    } else {
        result = 4;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xf0 | ((v >> 18) & 0x7) );
            utf8[offset+1] = (byte_t)( 0x80 | ((v >> 12) & 0x3f) );
            utf8[offset+2] = (byte_t)( 0x80 | ((v >> 6) & 0x3f) );
            utf8[offset+3] = (byte_t)( 0x80 |  (v & 0x3f) );
        }
    }
    return  result;
}

/* convert a UCS2 string into a UTF8 byte string, assumes 'buf' is correctly sized */
static int ucs2_to_utf8( cbytes_t  ucs2, int       ucs2len, bytes_t   buf ) {
    int  nn;
    int  result = 0;

    for (nn = 0; nn < ucs2len; ucs2 += 2, nn++) {
        int  c= (ucs2[0] << 8) | ucs2[1];
        result += utf8_write(buf, result, c);
    }
    return result;
}

static int quectel_at_cops(void) {
    int err;
    ATResponse *p_response = NULL;
    int response = 0;
    char *line;
    int mode, format, act = 0;
    char *oper;

    err = at_send_command_singleline("AT+COPS?", "+COPS:", &p_response);
    if ((err < 0) ||  (p_response == NULL) || (p_response->success == 0))
        goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

//+COPS:<mode>[,<format>[,<oper>][,<Act>]]
    err = at_tok_nextint(&line, &mode);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &format);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextstr(&line, &oper);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &act);
    if (err < 0) goto error;

error:
     at_response_free(p_response);
     return act;
}

static int quectel_at_creg(int response[4])  {
    int err;
    ATResponse *p_response = NULL;
    char *line;
    int commas;
    int skip;
    int count = 3;

    response[0] = response[1] = response[2] = response[3] = 0;

    err = at_send_command_singleline("AT+CREG?", "+CREG:", &p_response);
    if ((err < 0) ||  (p_response == NULL) || (p_response->success == 0))
        goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;
    
    err = at_tok_nextint(&line, &skip);
    if (err < 0) goto error;
    
    err = at_tok_nextint(&line, &response[0]);
    if (err < 0) goto error;
    
    err = at_tok_nexthexint(&line, &response[1]);
    if (err < 0) goto error;
    
    err = at_tok_nexthexint(&line, &response[2]);
    if (err < 0) goto error;
    
    err = at_tok_nexthexint(&line, &response[3]);
    if (err < 0) goto error;
    
error:
    at_response_free(p_response);
    return 0;
}
#endif

static int clccStateToRILState(int state, RIL_CallState *p_state)

{
    switch(state) {
        case 0: *p_state = RIL_CALL_ACTIVE;   return 0;
        case 1: *p_state = RIL_CALL_HOLDING;  return 0;
        case 2: *p_state = RIL_CALL_DIALING;  return 0;
        case 3: *p_state = RIL_CALL_ALERTING; return 0;
        case 4: *p_state = RIL_CALL_INCOMING; return 0;
        case 5: *p_state = RIL_CALL_WAITING;  return 0;
        default: return -1;
    }
}

/**
 * Note: directly modified line and has *p_call point directly into
 * modified line
 */
static int callFromCLCCLine(char *line, RIL_Call *p_call)
{
        //+CLCC: 1,0,2,0,0,\"+18005551212\",145
        //     index,isMT,state,mode,isMpty(,number,TOA)?

    int err;
    int state;
    int mode;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(p_call->index));
    if (err < 0) goto error;

    err = at_tok_nextbool(&line, &(p_call->isMT));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &state);
    if (err < 0) goto error;

    err = clccStateToRILState(state, &(p_call->state));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &mode);
    if (err < 0) goto error;

    p_call->isVoice = (mode == 0);

    err = at_tok_nextbool(&line, &(p_call->isMpty));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(p_call->number));

        /* tolerate null here */
        if (err < 0) return 0;

        // Some lame implementations return strings
        // like "NOT AVAILABLE" in the CLCC line
        if (p_call->number != NULL
            && 0 == strspn(p_call->number, "+0123456789")
        ) {
            p_call->number = NULL;
        }

        err = at_tok_nextint(&line, &p_call->toa);
        if (err < 0) goto error;
    }

    p_call->uusInfo = NULL;

    return 0;

error:
    LOGE("invalid CLCC line\n");
    return -1;
}


/** do post-AT+CFUN=1 initialization */
static void onRadioPowerOn()
{
    pollSIMState(NULL);
}

/** do post- SIM ready initialization */
static void onSIMReady()
{
    onSMSReady(NULL);
    
    /*  Call Waiting notifications */
    at_send_command("AT+CCWA=1", NULL);

    /*  Alternating voice/data off */
    at_send_command("AT+CMOD=0", NULL);

    /*  Not muted */
    at_send_command("AT+CMUT=0", NULL);

    /*  +CSSU unsolicited supp service notifications */
    at_send_command("AT+CSSN=0,1", NULL);

    /*  no connected line identification */
    at_send_command("AT+COLP=0", NULL);

    at_send_command("AT+CSCS=\"UCS2\"", NULL);
    if (ql_is_UC20)
        at_send_command("at+qcfg=\"ussd/cause\",1", NULL);

    /*  USSD unsolicited */
    at_send_command("AT+CUSD=1", NULL);

    at_send_command("AT+CGEREP=0", NULL); //carl tmp disable
}

static void requestRadioPower(void *data, size_t datalen, RIL_Token t)
{
    int onOff;

    int err;
    ATResponse *p_response = NULL;
    
    assert (datalen >= sizeof(int *));
    onOff = ((int *)data)[0];

    if (onOff == 0 && sState != RADIO_STATE_OFF) {
 #if 1 //quectel        
       /**
         *  Wythe modify on 2013-10-8
         *  just switch off the RF. CFUN=0 will shutdown the simcard.
         */
        err = at_send_command("AT+CFUN=4", &p_response);
#else   
        err = at_send_command("AT+CFUN=0", &p_response);
#endif
       if (err < 0 || p_response->success == 0) goto error;
        setRadioState(RADIO_STATE_OFF);
    } else if (onOff > 0 && sState == RADIO_STATE_OFF) {
        err = at_send_command("AT+CFUN=1", &p_response);
        if (err < 0|| p_response->success == 0) {     
            // Some stacks return an error when there is no SIM,
            // but they really turn the RF portion on
            // So, if we get an error, let's check to see if it
            // turned on anyway
            
            if (isRadioOn() != 1) {
                goto error;
            }
        }
        setRadioState(RADIO_STATE_SIM_NOT_READY);
    }

    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    LOGE("[%s] error", __func__);
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestOrSendDataCallList(RIL_Token *t);

static void onDataCallListChanged(void *param)
{
    requestOrSendDataCallList(NULL);
}

static void requestDataCallList(void *data, size_t datalen, RIL_Token t)
{
    requestOrSendDataCallList(&t);
}

static void get_local_ip(char *local_ip) {
    int inet_sock;
    struct ifreq ifr;
    char *ip = NULL;
    struct in_addr addr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, PPP_TTY_PATH);

    if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0) {
        strcpy(local_ip, "0.0.0.0");
        goto error;
    }
    memcpy (&addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof (struct in_addr));
    ip = inet_ntoa(addr);
    strcpy(local_ip, ip);
error:
    close(inet_sock);
}

static void requestOrSendDataCallList(RIL_Token *t)
{
    ATResponse *p_response;
    ATLine *p_cur;
    int err;
    int n = 0;
    char *out;
    char propKey[PROPERTY_VALUE_MAX];
    char propValue[PROPERTY_VALUE_MAX];

    err = at_send_command_multiline ("AT+CGACT?", "+CGACT:", &p_response);
    if (err != 0 || p_response->success == 0) {
        if (t != NULL)
            RIL_onRequestComplete(*t, RIL_E_GENERIC_FAILURE, NULL, 0);
        else
            RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                      NULL, 0);
        return;
    }

#if 1// quectel //Android only use CID 1
    if ((p_cur = p_response->p_intermediates) != NULL)
#else
    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next)
#endif
        n++;

    RIL_Data_Call_Response_v6 *responses =
        alloca(n * sizeof(RIL_Data_Call_Response_v6));

    int i;
    for (i = 0; i < n; i++) {
        responses[i].status = -1;
        responses[i].suggestedRetryTime = -1;
        responses[i].cid = -1;
        responses[i].active = -1;
#if 1 //quectel
        responses[i].type = (char *)"";
        responses[i].ifname = (char *)PPP_TTY_PATH;
        responses[i].addresses = (char *)"";
        responses[i].dnses = (char *)"";
        responses[i].gateways = (char *)"";
#else
        responses[i].type = "";
        responses[i].ifname = "";
        responses[i].addresses = "";
        responses[i].dnses = "";
        responses[i].gateways = "";
#endif
    }

    RIL_Data_Call_Response_v6 *response = responses;
#if 1 // quectel //Android only use CID 1
    if ((p_cur = p_response->p_intermediates) != NULL) {
#else
    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next) {
#endif
        char *line = p_cur->line;

        err = at_tok_start(&line);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response->cid);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response->active);
        if (err < 0)
            goto error;

        response++;
    }

    at_response_free(p_response);

    err = at_send_command_multiline ("AT+CGDCONT?", "+CGDCONT:", &p_response);
    if (err != 0 || p_response->success == 0) {
        if (t != NULL)
            RIL_onRequestComplete(*t, RIL_E_GENERIC_FAILURE, NULL, 0);
        else
            RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                      NULL, 0);
        return;
    }

#if 1 // quectel //Android only use CID 1
    if ((p_cur = p_response->p_intermediates) != NULL) {
#else
    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next) {
#endif
        char *line = p_cur->line;
        int cid;

        err = at_tok_start(&line);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &cid);
        if (err < 0)
            goto error;

        for (i = 0; i < n; i++) {
            if (responses[i].cid == cid)
                break;
        }

        //if (i >= n) {
        //    /* details for a context we didn't hear about in the last request */
        //    continue;
        //}

        // Assume no error
        responses[i].status = 0;

        // type
        err = at_tok_nextstr(&line, &out);
        if (err < 0)
            goto error;
        responses[i].type = alloca(strlen(out) + 1);
        strcpy(responses[i].type, out);

        // APN ignored for v5
        err = at_tok_nextstr(&line, &out);
        if (err < 0)
            goto error;

        responses[i].ifname = strdup(PPP_TTY_PATH);

        get_local_ip(propValue);
        responses[i].addresses = strdup(propValue);

        responses[i].dnses = alloca(4*6+4*6);
        sprintf(propKey, "net.%s.dns1", PPP_TTY_PATH);
        property_get(propKey, propValue, "8.8.8.8");
        strcpy(responses[i].dnses, propValue);
        strcat(responses[i].dnses, " ");
        sprintf(propKey, "net.%s.dns2", PPP_TTY_PATH);
        property_get(propKey, propValue, "8.8.4.4");
        strcat(responses[i].dnses, propValue);
    }

    at_response_free(p_response);

    propKey[0] = '\0';
    sprintf(propKey, "net.%s.gw", PPP_TTY_PATH);
    if (property_get(propKey, propValue, NULL) <= 0) {
        sprintf(propKey, "net.%s.remote-ip", PPP_TTY_PATH);
        if (property_get(propKey, propValue, NULL) <= 0) {
            sprintf(propKey, "net.%s.gw", "gprs");
            if (property_get(propKey, propValue, NULL) <= 0) {
                sprintf(propKey, "net.%s.remote-ip", "gprs");
                property_get(propKey, propValue, responses[i].addresses); //quectel, gateways is no mean for wwan
            }
        }
    }
    responses[i].gateways = strdup(propValue);

    LOGD("type: %s", responses[i].type);
    LOGD("ifname: %s", responses[i].ifname);
    LOGD("addresses: %s", responses[i].addresses);
    LOGD("dnses: %s", responses[i].dnses);
    LOGD("gateways: %s", responses[i].gateways);

    if (t != NULL)
        RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                              n * sizeof(RIL_Data_Call_Response_v6));
    else
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                  responses,
                                  n * sizeof(RIL_Data_Call_Response_v6));

    return;

error:
    LOGE("%s error", __func__);
    if (t != NULL)
        RIL_onRequestComplete(*t, RIL_E_GENERIC_FAILURE, NULL, 0);
    else
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                  NULL, 0);

    at_response_free(p_response);
}

static void requestQueryNetworkSelectionMode(
                void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *p_response = NULL;
    int response = 0;
    char *line;

    err = at_send_command_singleline("AT+COPS?", "+COPS:", &p_response);

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);

    if (err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line, &response);

    if (err < 0) {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    at_response_free(p_response);
    return;
error:
    LOGE("%s error", __func__);
    at_response_free(p_response);
    LOGE("requestQueryNetworkSelectionMode must never return error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void sendCallStateChanged(void *param)
{
    RIL_onUnsolicitedResponse (
        RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
        NULL, 0);
}

static void requestGetCurrentCalls(void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *p_response;
    ATLine *p_cur;
    int countCalls;
    int countValidCalls;
    RIL_Call *p_calls;
    RIL_Call **pp_calls;
    int i;
    int needRepoll = 0;

    err = at_send_command_multiline ("AT+CLCC", "+CLCC:", &p_response);

    if (err != 0 || p_response->success == 0) {
        LOGE("%s response generic failure", __func__);
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    /* count the calls */
    for (countCalls = 0, p_cur = p_response->p_intermediates
            ; p_cur != NULL
            ; p_cur = p_cur->p_next
    ) {
        countCalls++;
    }

    /* yes, there's an array of pointers and then an array of structures */

    pp_calls = (RIL_Call **)alloca(countCalls * sizeof(RIL_Call *));
    p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
    memset (p_calls, 0, countCalls * sizeof(RIL_Call));

    /* init the pointer array */
    for(i = 0; i < countCalls ; i++) {
        pp_calls[i] = &(p_calls[i]);
    }

    for (countValidCalls = 0, p_cur = p_response->p_intermediates
            ; p_cur != NULL
            ; p_cur = p_cur->p_next
    ) {
        err = callFromCLCCLine(p_cur->line, p_calls + countValidCalls);

        if (err != 0) {
            continue;
        }

        if (p_calls[countValidCalls].state != RIL_CALL_ACTIVE
            && p_calls[countValidCalls].state != RIL_CALL_HOLDING
        ) {
            needRepoll = 1;
        }
#if 1 //quectel
        if(p_calls[countValidCalls].isVoice)
#endif
        countValidCalls++;
    }

    LOGI("Calls=%d,Valid=%d",countCalls,countValidCalls);
    
    RIL_onRequestComplete(t, RIL_E_SUCCESS, pp_calls,
            countValidCalls * sizeof (RIL_Call *));

    at_response_free(p_response);

#ifdef POLL_CALL_STATE
    if (countValidCalls) {  // We don't seem to get a "NO CARRIER" message from
                            // smd, so we're forced to poll until the call ends.
#else
    if (needRepoll) {
#endif
        RIL_requestTimedCallback (sendCallStateChanged, NULL, &TIMEVAL_CALLSTATEPOLL);
    }

    return;
error:
    LOGD("%s error", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestDial(void *data, size_t datalen, RIL_Token t)
{
    RIL_Dial *p_dial;
    char *cmd;
    const char *clir;
    int ret;

    p_dial = (RIL_Dial *)data;

    switch (p_dial->clir) {
        case 1: clir = "I"; break;  /*invocation*/
        case 2: clir = "i"; break;  /*suppression*/
        default:
        case 0: clir = ""; break;   /*subscription default*/
    }

    asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);

    ret = at_send_command(cmd, NULL);

    free(cmd);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestWriteSmsToSim(void *data, size_t datalen, RIL_Token t)
{
    RIL_SMS_WriteArgs *p_args;
    char *cmd;
    int length;
    int err;
    ATResponse *p_response = NULL;

    p_args = (RIL_SMS_WriteArgs *)data;

    length = strlen(p_args->pdu)/2;
    asprintf(&cmd, "AT+CMGW=%d,%d", length, p_args->status);

    err = at_send_command_sms(cmd, p_args->pdu, "+CMGW:", &p_response);

    if (err != 0 || p_response->success == 0) goto error;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);

    return;
error:
    LOGE("%s error\n", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestHangup(void *data, size_t datalen, RIL_Token t)
{
    int *p_line;

    int ret;
    char *cmd;

    p_line = (int *)data;

    // 3GPP 22.030 6.5.5
    // "Releases a specific active call X"
    asprintf(&cmd, "AT+CHLD=1%d", p_line[0]);

    ret = at_send_command(cmd, NULL);

    free(cmd);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestSignalStrength(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
    int response[2];
    char *line;

    if (s_closed && (currentState() == RADIO_STATE_SIM_READY)) {
        RIL_SignalStrength_v6 signalStrength;
        memset(&signalStrength, 0, sizeof(RIL_SignalStrength_v6));
        /**
        *  In Android Jelly Bean, the invalid value for
        *  LET signalStrength should be 99 depending on the SignalStrength.java.
        */
        //#if ((PLATFORM_VERSION >= 420) || ((PLATFORM_VERSION < 100) && (PLATFORM_VERSION >= 42)))
        if (RIL_VERSION >= 7) {
            signalStrength.LTE_SignalStrength.signalStrength = 99;
            signalStrength.LTE_SignalStrength.rsrp = 0x7FFFFFFF;
            signalStrength.LTE_SignalStrength.rsrq = 0x7FFFFFFF;
            signalStrength.LTE_SignalStrength.rssnr = 0x7FFFFFFF;
            signalStrength.LTE_SignalStrength.cqi = 0x7FFFFFFF;
        } else {
            signalStrength.LTE_SignalStrength.signalStrength = -1;
            signalStrength.LTE_SignalStrength.rsrp = -1;
            signalStrength.LTE_SignalStrength.rsrq = -1;
            signalStrength.LTE_SignalStrength.rssnr = -1;
            signalStrength.LTE_SignalStrength.cqi = -1;
        }	
        signalStrength.GW_SignalStrength.signalStrength = 31;
        signalStrength.GW_SignalStrength.bitErrorRate = 0;
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &signalStrength, sizeof(RIL_SignalStrength_v6));
        return;
    }

    err = at_send_command_singleline("AT+CSQ", "+CSQ:", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(response[0]));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(response[1]));
    if (err < 0) goto error;

#if 1 //quectel
{
    RIL_SignalStrength_v6 signalStrength;
    memset(&signalStrength, 0, sizeof(RIL_SignalStrength_v6));
    /**
     *  In Android Jelly Bean, the invalid value for
     *  LET signalStrength should be 99 depending on the SignalStrength.java.
     */
//#if ((PLATFORM_VERSION >= 420) || ((PLATFORM_VERSION < 100) && (PLATFORM_VERSION >= 42)))
if (RIL_VERSION >= 7) {
    signalStrength.LTE_SignalStrength.signalStrength = 99;
    signalStrength.LTE_SignalStrength.rsrp = 0x7FFFFFFF;
    signalStrength.LTE_SignalStrength.rsrq = 0x7FFFFFFF;
    signalStrength.LTE_SignalStrength.rssnr = 0x7FFFFFFF;
    signalStrength.LTE_SignalStrength.cqi = 0x7FFFFFFF;
} else {
    signalStrength.LTE_SignalStrength.signalStrength = -1;
    signalStrength.LTE_SignalStrength.rsrp = -1;
    signalStrength.LTE_SignalStrength.rsrq = -1;
    signalStrength.LTE_SignalStrength.rssnr = -1;
    signalStrength.LTE_SignalStrength.cqi = -1;
}	
    signalStrength.GW_SignalStrength.signalStrength = response[0];
    signalStrength.GW_SignalStrength.bitErrorRate = response[1];
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &signalStrength, sizeof(RIL_SignalStrength_v6));
}
#else
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
#endif

#if 1 // some UG95 fireware donot report +CGREG/+CREG when network state change
    if (ql_is_UG95) {
        static int old_response[4];
        int new_response[4];
        quectel_at_creg(new_response);
        if (memcmp(new_response, old_response, sizeof(old_response))) {
            memcpy(old_response, new_response, sizeof(old_response));
            RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,NULL, 0);
        }
    }
#endif

    at_response_free(p_response);
    return;

error:
    LOGE("requestSignalStrength must never return an error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestRegistrationState(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int response[4];
    char * responseStr[4];
    ATResponse *p_response = NULL;
    const char *cmd;
    const char *prefix;
    char *line, *p;
    int commas;
    int skip;
    int count = 3;


    if (request == RIL_REQUEST_VOICE_REGISTRATION_STATE) {
        cmd = "AT+CREG?";
        prefix = "+CREG:";
    } else if (request == RIL_REQUEST_DATA_REGISTRATION_STATE) {
        cmd = "AT+CGREG?";
        prefix = "+CGREG:";
    } else {
        assert(0);
        goto error;
    }

#if 1 //quectel
__requestRegistrationState_restart:
    skip = 2; //unsolicited result code with location information +CGREG: 2,<stat>[,<lac>,<ci>[,<Act>]]
#endif
    err = at_send_command_singleline(cmd, prefix, &p_response);

    if (err != 0) goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    /* Ok you have to be careful here
     * The solicited version of the CREG response is
     * +CREG: n, stat, [lac, cid]
     * and the unsolicited version is
     * +CREG: stat, [lac, cid]
     * The <n> parameter is basically "is unsolicited creg on?"
     * which it should always be
     *
     * Now we should normally get the solicited version here,
     * but the unsolicited version could have snuck in
     * so we have to handle both
     *
     * Also since the LAC and CID are only reported when registered,
     * we can have 1, 2, 3, or 4 arguments here
     *
     * finally, a +CGREG: answer may have a fifth value that corresponds
     * to the network type, as in;
     *
     *   +CGREG: n, stat [,lac, cid [,networkType]]
     */

    /* count number of commas */
    commas = 0;
    for (p = line ; *p != '\0' ;p++) {
        if (*p == ',') commas++;
    }

    switch (commas) {
        case 0: /* +CREG: <stat> */
            err = at_tok_nextint(&line, &response[0]);
            if (err < 0) goto error;
            response[1] = -1;
            response[2] = -1;
        break;

        case 1: /* +CREG: <n>, <stat> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &response[0]);
            if (err < 0) goto error;
            response[1] = -1;
            response[2] = -1;
            if (err < 0) goto error;
        break;

        case 2: /* +CREG: <stat>, <lac>, <cid> */
            err = at_tok_nextint(&line, &response[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[2]);
            if (err < 0) goto error;
        break;
        case 3: /* +CREG: <n>, <stat>, <lac>, <cid> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &response[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[2]);
            if (err < 0) goto error;
            if (((response[0] == 1) || (response[0] == 5)) && ql_is_GSM) {
                response[3] = 0; //force RADIO_TECH_GPRS
                count = 4;
            }
        break;
        /* special case for CGREG, there is a fourth parameter
         * that is the network type (unknown/gprs/edge/umts)
         */
        case 4: /* +CGREG: <n>, <stat>, <lac>, <cid>, <networkType> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &response[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[2]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &response[3]);
            if (err < 0) goto error;
#if 1 //quectel UC15&UC20&UG95 canot get raido tech from AT+CGREG?, what about EC20?
            if ((request == RIL_REQUEST_DATA_REGISTRATION_STATE) && (response[3] == 2)) {
                int real_act = quectel_at_cops();
                if (real_act > response[3])
                    response[3] = real_act;
            }
#endif
            count = 4;
        break;
        default:
            goto error;
    }

#if 1 // using china-telecom 4G sim card, cannot register voice serice
//frameworks\base\packages\SystemUI\src\com\android\systemui\statusbar\policy\NetworkController.java updateTelephonySignalStrength()
    if (ql_is_EC20 && (request == RIL_REQUEST_VOICE_REGISTRATION_STATE)
        && currentDataServiceState() && (response[0] != 1) && (response[0] != 5)
        && !strcmp(cmd, "AT+CREG?")) {
        cmd = "AT+CGREG?";
        prefix = "+CGREG:";
        goto __requestRegistrationState_restart;
    }
#endif

    asprintf(&responseStr[0], "%d", response[0]);
    asprintf(&responseStr[1], "%x", response[1]);
    asprintf(&responseStr[2], "%x", response[2]);

#if 1 //quectel
    if (skip != 2) {
        at_response_free(p_response);
        p_response = NULL;
        at_send_command("AT+CREG=2", NULL); 
        at_send_command("AT+CGREG=2", NULL); 
        goto __requestRegistrationState_restart;
    }

    if (request == RIL_REQUEST_DATA_REGISTRATION_STATE) {
        setDataServiceState((response[0] == 1) || (response[0] == 5));
        if (currentDataServiceState() && !time_zone_report) {
            ATResponse *p_response = NULL;
            int err = at_send_command_singleline("AT+QLTS", "+QLTS", &p_response);
            if (!(err < 0  || p_response == NULL || p_response->success == 0)) {
                //+QLTS: "13/08/23,06:51:13+32,0"
                char *response;
                char *line = strdup(p_response->p_intermediates->line);
                at_tok_start(&line);
                err = at_tok_nextstr(&line, &response);

                if (err != 0) {
                    LOGE("invalid QLTS line %s\n", p_response->p_intermediates->line);
                } else {
                    RIL_onUnsolicitedResponse (RIL_UNSOL_NITZ_TIME_RECEIVED, response, strlen(response));
                }
            }
            at_response_free(p_response);
            time_zone_report = 1;
        }
    }
    
    if (count == 3) {
        if ((response[1] == -1) && (response[2] == -1)) {
            //to advoid throw <java.lang.NumberFormatException: Invalid int: "ffffffff"> in GsmServiceStateTracker.java
            count = 1;
        }
    } else if (count > 3) {
        RIL_RadioTechnology radio_tech = RADIO_TECH_UNKNOWN;
        switch (response[3]) {
               case 0: //GSM (Not support on UC20-A)
                    radio_tech = RADIO_TECH_GPRS;
                break;
                case 2: //UTRAN
                    radio_tech = RADIO_TECH_UMTS;
                break;
                case 3: //GSM W/EGPRS
                    radio_tech = RADIO_TECH_EDGE;
                break;
                case 4: //UTRAN W/HSDPA
                    radio_tech = RADIO_TECH_HSDPA;
                break;
                case 5: //UTRAN W/HSUPA
                    radio_tech = RADIO_TECH_HSUPA;
                break;
               case 6: //UTRAN W/HSDPA and HSUPA
                    radio_tech = RADIO_TECH_HSPA;
                break;
               case 7: //LTE
                    radio_tech = RADIO_TECH_LTE;
                break;
                default:
                    radio_tech = RADIO_TECH_UNKNOWN;
                break;
        }
        response[3] = radio_tech;
    }
#endif  

    if (count > 3)
        asprintf(&responseStr[3], "%d", response[3]);

    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, count*sizeof(char*));
    at_response_free(p_response);

    return;
error:
    LOGE("requestRegistrationState must never return an error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestOperator(void *data, size_t datalen, RIL_Token t)
{
    int err;
    int i;
    int skip;
    ATLine *p_cur;
    char *response[3];

#if 1 //quectel
__requestOperator_restart:
#endif
    memset(response, 0, sizeof(response));

    ATResponse *p_response = NULL;

    err = at_send_command_multiline(
        "AT+COPS=3,0;+COPS?;+COPS=3,1;+COPS?;+COPS=3,2;+COPS?",
        "+COPS:", &p_response);

    /* we expect 3 lines here:
     * +COPS: 0,0,"T - Mobile"
     * +COPS: 0,1,"TMO"
     * +COPS: 0,2,"310170"
     */

    if (err != 0) goto error;

    for (i = 0, p_cur = p_response->p_intermediates
            ; p_cur != NULL
            ; p_cur = p_cur->p_next, i++
    ) {
        char *line = p_cur->line;

        err = at_tok_start(&line);
        if (err < 0) goto error;

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        // If we're unregistered, we may just get
        // a "+COPS: 0" response
        if (!at_tok_hasmore(&line)) {
            response[i] = NULL;
            continue;
        }

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        // a "+COPS: 0, n" response is also possible
        if (!at_tok_hasmore(&line)) {
            response[i] = NULL;
            continue;
        }

        err = at_tok_nextstr(&line, &(response[i]));
        if (err < 0) goto error;
    }

    if (i != 3) {
        /* expect 3 lines exactly */
        goto error;
    }

#if 1 //quectel
    if (!response[0] && !response[1] && !response[2] && (network_debounce_time > 0)) {
        sleep(1);
        network_debounce_time--;
        at_response_free(p_response);
        goto __requestOperator_restart;
    }     
    network_debounce_time = 0;
#endif

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);

    return;
error:
    LOGE("requestOperator must not return error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestSendSMS(void *data, size_t datalen, RIL_Token t)
{
    int err;
    const char *smsc;
    const char *pdu;
    int tpLayerLength;
    char *cmd1, *cmd2;
    RIL_SMS_Response response;
    ATResponse *p_response = NULL;

    smsc = ((const char **)data)[0];
    pdu = ((const char **)data)[1];

    tpLayerLength = strlen(pdu)/2;

    // "NULL for default SMSC"
    if (smsc == NULL) {
        smsc= "00";
    }

    asprintf(&cmd1, "AT+CMGS=%d", tpLayerLength);
    asprintf(&cmd2, "%s%s", smsc, pdu);

    err = at_send_command_sms(cmd1, cmd2, "+CMGS:", &p_response);

    if (err != 0 || p_response->success == 0) goto error;

    memset(&response, 0, sizeof(response));

    /* FIXME fill in messageRef and ackPDU */

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    at_response_free(p_response);

    return;
error:
    LOGE("%s error", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

/*
 * RIL_REQUEST_SEND_SMS_EXPECT_MORE
 */
void requestSendSMSExpectMore(void *data, size_t datalen, RIL_Token t)
{
        (void) data; (void) datalen;

    at_send_command("AT+CMMS=1",NULL);

        requestSendSMS(data, datalen, t);
}

//update:Joe.Wang 2014-1-13
static void requestSetupDataCall(void *data, size_t datalen, RIL_Token t)
{
    const char *apn;
    const char *user = NULL;
    const char *pass = NULL;
    const char *auth_type = NULL;
    const char *pdp_type = "IP";
    char *cmd;
    int err;
    int retry = 0;
    pid_t ql_pppd_pid;
    ATResponse *p_response = NULL;

    char ppp_local_ip[PROPERTY_VALUE_MAX] = {'\0'};
    struct timeval begin_tv, end_tv;
    gettimeofday(&begin_tv, NULL);
    
    apn = ((const char **)data)[2];
    if (datalen > 3 * sizeof(char *))
        user = ((char **)data)[3];
    if (datalen > 4 * sizeof(char *))
        pass = ((char **)data)[4];
    if (datalen > 5 * sizeof(char *))
        auth_type = ((const char **)data)[5]; // 0 ~ NONE, 1 ~ PAP, 1 ~ CHAP, 3 ~ PAP / CHAP
    if (datalen > 6 * sizeof(char *))
        pdp_type = ((const char **)data)[6];

    LOGI("*************************************");
    LOGI("USER:%s",user);
    LOGI("PASS:%s",pass);
    LOGI("auth_type:%s",auth_type);
    LOGI("pdp_type:%s",pdp_type);
    LOGI("*************************************");

#if 1 // quectel Set DTR Function Mode 
//ON->OFF on DTR: Disconnect data call, change to command mode. During state DTR = OFF, auto-answer function is disabled
    at_send_command("AT&D2", NULL);
#endif

     //Make sure there is no existing connection or pppd instance running
    if (!strncmp(PPP_TTY_PATH, "ppp", 3))
        ql_pppd_stop(SIGKILL);
    else
        ql_ndis_stop(SIGKILL);
    
    if (currentDataServiceState() == 0) {
        RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
        LOGE("gprsState is out of service!");
        goto error;
    }
    
    LOGD("requesting data connection to APN '%s'!\n", apn);
     
    asprintf(&cmd, "AT+CGDCONT=1,\"%s\",\"%s\"", pdp_type, apn);

    //FIXME check for error here
    err = at_send_command(cmd, NULL);
    free(cmd);

    PPP_TTY_PATH = "ppp0";
    /* start the gprs pppd */
    if (ql_mux_enabled)
        ql_pppd_pid = ql_pppd_start(CMUX_PPP_PORT, user, pass, auth_type);
    else {
        char *usbnet_adapeter = NULL;
        if ((ql_is_UC20 || ql_is_EC20) && !access("/system/bin/quectel-CM", X_OK) && !ql_get_ndisname(&usbnet_adapeter) && usbnet_adapeter) {
            PPP_TTY_PATH = usbnet_adapeter;
            ql_pppd_pid = ql_ndis_start(apn, user, pass, auth_type);
        } else {
            ql_pppd_pid = ql_pppd_start(NULL, user, pass, auth_type);
        }
    }
    if (ql_pppd_pid < 0)
        goto error;

    sleep(3);
    while (!s_closed && (retry++ < 50)) {
        if ((waitpid(ql_pppd_pid, NULL, WNOHANG)) == ql_pppd_pid)
            goto error;
        get_local_ip(ppp_local_ip);
        LOGD("[%d] trying to get_local_ip ... %s", retry, ppp_local_ip);
        if(strcmp(ppp_local_ip, "0.0.0.0"))
            break;
        sleep(1);
    }
    gettimeofday(&end_tv, NULL);
    LOGD("get_local_ip: %s, cost %ld sec", ppp_local_ip, (end_tv.tv_sec - begin_tv.tv_sec));
    if(strlen(ppp_local_ip) <= 6)
        goto error;

    requestOrSendDataCallList(&t);
    at_response_free(p_response);

#if 1 // quectel Set DTR Function Mode 
    if (USB_HOST_SUSPEND_SUPPORT == 0) //if the usb host donot support suspend
        at_send_command("AT&D0", NULL); //TA ignores status on DTR, will donot disconnect ppp when DTR is assert
#endif
    return;

error:
    if (!strncmp(PPP_TTY_PATH, "ppp", 3))
        ql_pppd_stop(SIGKILL);
    else
        ql_ndis_stop(SIGKILL);
    LOGE("Unable to setup PDP in %s\n", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestSMSAcknowledge(void *data, size_t datalen, RIL_Token t)
{
    int ackSuccess;
    int err;

    ackSuccess = ((int *)data)[0];

    if (ackSuccess == 1) {
        err = at_send_command("AT+CNMA=1", NULL);
    } else if (ackSuccess == 0)  {
        err = at_send_command("AT+CNMA=2", NULL);
    } else {
        LOGE("unsupported arg to RIL_REQUEST_SMS_ACKNOWLEDGE\n");
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    LOGE("%s error", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

}

#if 1 //usim -> sim
typedef struct __TLV {
    unsigned char tag;
    unsigned char len;
    unsigned char data[0];
} TLV;

static int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return (c - '0');
    if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
    return 0;
}

static int hexStringToBytes(const char * s, unsigned char *d) {
    int sz, i;

    if (!s || !strlen(s))
        return 0;

    sz = strlen(s) / 2;

    for (i = 0; i < sz ; i++) {
        d[i] = (unsigned char) ((hexCharToInt(s[i*2 + 0]) << 4) | hexCharToInt(s[i*2 + 1]));
    }

    return sz;
}

static TLV * getTLV(const unsigned char *d, unsigned char tag) {
     TLV *tlv = (TLV *)d;
     int sz = tlv->len;

     tlv++; //skip head

     while (sz) {
        if (tlv->tag != tag) {
            tlv = (TLV *)(((char *)tlv) + sizeof(TLV) + tlv->len);
            sz -= sizeof(TLV) + tlv->len;
        } else {
        #if 0
            int i;
            printf("{%02x, %02x, ", tlv->tag, tlv->len);
            for (i = 0; i < tlv->len; i++)
                printf("%02x, ", tlv->data[i]);
            printf("}\n");
        #endif
            return tlv;
        }
    }
    return NULL;
}

//frameworks\base\telephony\java\com\android\internal\telephony\IccFileHandler.java
//from TS 11.11 9.1 or elsewhere
const int COMMAND_GET_RESPONSE = 0xc0;

//***** types of files  TS 11.11 9.3
static const int EF_TYPE_TRANSPARENT = 0;
static const int EF_TYPE_LINEAR_FIXED = 1;
static const int EF_TYPE_CYCLIC = 3;

//***** types of files  TS 11.11 9.3
const int TYPE_RFU = 0;
const int TYPE_MF  = 1;
const int TYPE_DF  = 2;
const int TYPE_EF  = 4;

// Byte order received in response to COMMAND_GET_RESPONSE
// Refer TS 51.011 Section 9.2.1
const int RESPONSE_DATA_RFU_1 = 0;
const int RESPONSE_DATA_RFU_2 = 1;

const int RESPONSE_DATA_FILE_SIZE_1 = 2;
const int RESPONSE_DATA_FILE_SIZE_2 = 3;

const int RESPONSE_DATA_FILE_ID_1 = 4;
const int RESPONSE_DATA_FILE_ID_2 = 5;
const int RESPONSE_DATA_FILE_TYPE = 6;
const int RESPONSE_DATA_RFU_3 = 7;
const int RESPONSE_DATA_ACCESS_CONDITION_1 = 8;
const int RESPONSE_DATA_ACCESS_CONDITION_2 = 9;
const int RESPONSE_DATA_ACCESS_CONDITION_3 = 10;
const int RESPONSE_DATA_FILE_STATUS = 11;
const int RESPONSE_DATA_LENGTH = 12;
const int RESPONSE_DATA_STRUCTURE = 13;
const int RESPONSE_DATA_RECORD_LENGTH = 14;

void usim2sim(RIL_SIM_IO_Response *psr) {
    int sz;
    int i;
    unsigned char usim_data[1024];
    unsigned char sim_data[15] = {0};
    static char new_response[31];
    TLV * tlv;
    const char bytesToHexString[] = "0123456789abcdef";

    if (!psr->simResponse)
        return;

    if (!strlen(psr->simResponse)) {
        psr->simResponse = NULL;
        return;    
    }
    
    if (strlen(psr->simResponse) < 4)
        return;

    sz = hexStringToBytes(psr->simResponse, usim_data);

    if (usim_data[0] != 0x62) {
        //LOGD("CRSM: not usim");
        return;
    }

    if (usim_data[1] != (sz - 2)) {
        //LOGD("CRSM: error usim len");
        return;
    }

    tlv = getTLV(usim_data, 0x80);
    if (tlv) {
        //LOGD("CRSM: FILE_SIZE %02X%02X", tlv->data[0], tlv->data[1]);
        sim_data[RESPONSE_DATA_FILE_SIZE_1] = tlv->data[0];
        sim_data[RESPONSE_DATA_FILE_SIZE_2] = tlv->data[1];
    }   

    tlv = getTLV(usim_data, 0x83);
    if (tlv) {
        //LOGD("CRSM: FILE_ID %02X%02X", tlv->data[0], tlv->data[1]);
        sim_data[RESPONSE_DATA_FILE_ID_1] = tlv->data[0];
        sim_data[RESPONSE_DATA_FILE_ID_2] = tlv->data[1];
    }

    tlv = getTLV(usim_data, 0x82);
    if (tlv) {
        int filetype = (tlv->data[0] >> 3) & 0x7;
        int efstruct = (tlv->data[0] >> 0) & 0x7;
        //LOGD("CRSM: len: %d, %02x %02x %02x %02x %02x", tlv->len, tlv->data[0], tlv->data[1], tlv->data[2], tlv->data[3], tlv->data[4]);
        
        //File type:
        if ((filetype == 0) || (filetype == 1)) {
            //LOGD("CRSM: FILE_TYPE_EF");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_EF;
        } else if ((filetype == 7) && (efstruct == 0)) {
            //LOGD("CRSM: TYPE_DF");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_DF;
        } else {
            //LOGD("CRSM: TYPE_RFU");
            sim_data[RESPONSE_DATA_FILE_TYPE] = TYPE_RFU;
        }

        //EF struct
        if (efstruct == 1) {
            //LOGD("CRSM: EF_TYPE_TRANSPARENT");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_TRANSPARENT;
        } else if (efstruct == 2) {
            //LOGD("CRSM: EF_TYPE_LINEAR_FIXED");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_LINEAR_FIXED;
        } else if (efstruct == 3) {
            //LOGD("CRSM: EF_TYPE_CYCLIC");
            sim_data[RESPONSE_DATA_STRUCTURE] = EF_TYPE_CYCLIC;    
         } else {
            //LOGD("CRSM: EF_TYPE_UNKNOWN");
         }

        if ((efstruct == 2) || (efstruct == 3)) {
            if (tlv->len == 5) {
                sim_data[RESPONSE_DATA_RECORD_LENGTH] = ((tlv->data[2] << 8) + tlv->data[3]) & 0xFF;
               //LOGD("CRSM: RESPONSE_DATA_RECORD_LENGTH %d", sim_data[RESPONSE_DATA_RECORD_LENGTH]); 
            } else {
                //LOGD("CRSM: must contain Record length and Number of records");
            }
        }
    }

    for (i = 0; i < 15; i++) {
        new_response[i*2 + 0] =  bytesToHexString[0x0f & (sim_data[i] >> 4)];
        new_response[i*2 + 1] =  bytesToHexString[0x0f & sim_data[i]];
    }
    new_response[30] = '\0';

    psr->simResponse = new_response;

//see telephony\src\java\com\android\internal\telephony\uicc\IccIoResult.java
#if 0
    /**
     * true if this operation was successful
     * See GSM 11.11 Section 9.4
     * (the fun stuff is absent in 51.011)
     */
    public boolean success() {
        return sw1 == 0x90 || sw1 == 0x91 || sw1 == 0x9e || sw1 == 0x9f;
    }
#endif
    if (psr->sw1 == 0x90 || psr->sw1 == 0x91 || psr->sw1 == 0x9e || psr->sw1 == 0x9f)
        ;
    else
        psr->sw1 = 0x90;

    return;
}
#endif

static void  requestSIM_IO(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    RIL_SIM_IO_Response sr;
    int err;
    char *cmd = NULL;
    RIL_SIM_IO_v6 *p_args;
    char *line;

    memset(&sr, 0, sizeof(sr));

    p_args = (RIL_SIM_IO_v6 *)data;
    
    /* FIXME handle pin2 */
#if 1 //quectel
    if (p_args->command == COMMAND_GET_RESPONSE) {
        p_args->p3 = 0;
    }
#endif

    if (p_args->data == NULL) {
        LOGI("[%s]: p_args->data is NULL\r\n", __func__);
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d",
                    p_args->command, p_args->fileid,
                    p_args->p1, p_args->p2, p_args->p3);
    } else {
#if 1 //quectel
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,\"%s\"",
#else
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,%s",
#endif
                    p_args->command, p_args->fileid,
                    p_args->p1, p_args->p2, p_args->p3, p_args->data);
    }
    
    err = at_send_command_singleline(cmd, "+CRSM:", &p_response);

    if (err < 0 || p_response->success == 0) {
        LOGI("[%s]: send +CRSM error\r\n", __func__);
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw1));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw2));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(sr.simResponse));
        if (err < 0) goto error;
    }

#if 1 //quectel
//see telephony\src\java\com\android\internal\telephony\uicc\IccFileHandler.java handleMessage() -> case EVENT_GET_BINARY_SIZE_DONE:
    if (p_args->command == COMMAND_GET_RESPONSE)
        usim2sim(&sr);
#endif

    LOGD("[%s]: RIL_SIM_IO_Response Complete sr.sw1=%d, sr.sw2=%d, sr.simResponse=%s\r\n",
        __func__, sr.sw1, sr.sw2, sr.simResponse);
    
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sr, sizeof(sr));
    at_response_free(p_response);
    free(cmd);

    return;
error:
    LOGE("%s error\n", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    free(cmd);

}

static int getRemainingTimes(int request)
{
    ATResponse *p_response = NULL;
    ATLine *p_cur = NULL;
    char *line = NULL;
    int err;
    //int n = 0;
    char *fac = NULL;
    int pin1_remaining_times; 
    int puk1_remaining_times;
    int pin2_remaining_times;
    int puk2_remaining_times;

    err = at_send_command_multiline("AT+QPINC?", "+QPINC", &p_response);
    //for (p_cur = p_response->p_intermediates; p_cur != NULL;
    //     p_cur = p_cur->p_next)
    //    n++;

    if(err < 0  || p_response == NULL || p_response->success == 0) goto error;
    
    for (p_cur = p_response->p_intermediates; p_cur != NULL;p_cur = p_cur->p_next) 
    {
        char *line = p_cur->line;

        at_tok_start(&line);

        err = at_tok_nextstr(&line,&fac);
        if(err < 0) goto error;

        if(!strncmp(fac,"SC",2))
        {
            err = at_tok_nextint(&line,&pin1_remaining_times);
            if(err < 0) goto error;
            err = at_tok_nextint(&line,&puk1_remaining_times);
            if(err < 0) goto error;
        }
        else if(!strncmp(fac,"P2",2))
        {
            err = at_tok_nextint(&line,&pin2_remaining_times);
            if(err < 0) goto error;
            err = at_tok_nextint(&line,&puk2_remaining_times);
            if(err < 0) goto error;
        }
        else
            goto error;
    }
    LOGI("PIN1:%d\nPIN2:%d\nPUN1:%d\nPUN2:%d",pin1_remaining_times,pin2_remaining_times,puk1_remaining_times,puk2_remaining_times);

    free(p_response);
    free(p_cur);
#if 0
    if(!strcmp(pinType,"PIN1")) return pin1_remaining_times;
    else  if(!strcmp(pinType,"PIN2")) return pin2_remaining_times; 
    else  if(!strcmp(pinType,"PUK1")) return puk1_remaining_times; 
    else  if(!strcmp(pinType,"PUK2")) return puk2_remaining_times; 
    else return -1;
#else
    switch(request)
    {
        case RIL_REQUEST_SET_FACILITY_LOCK:
        case RIL_REQUEST_ENTER_SIM_PIN:
        case RIL_REQUEST_CHANGE_SIM_PIN:
            return pin1_remaining_times;
        case RIL_REQUEST_ENTER_SIM_PIN2:
        case RIL_REQUEST_CHANGE_SIM_PIN2:
            return pin2_remaining_times;
        case RIL_REQUEST_ENTER_SIM_PUK:
            return puk1_remaining_times;
        case RIL_REQUEST_ENTER_SIM_PUK2:
            return puk2_remaining_times;
        default:
            return -1;
    }
#endif
error:
    return -1;
}

static void  requestQuestFacility(void*  data, size_t  datalen, RIL_Token  t)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    int status;
    char *fac = NULL;
    char *mode = "2";
    char *password = NULL;
    char *class = NULL;
    char *line = NULL;

    LOGE("%s Enter\n", __func__);

    fac = ((char **)data)[0];
    password = ((char **)data)[1];
    class = ((char **)data)[2];

    asprintf(&cmd,"AT+CLCK=\"%s\",%s,\"%s\",%s",fac,mode,password,class);
    err = at_send_command_singleline(cmd, "+CLCK:", &p_response);
    if(err < 0  || p_response == NULL || p_response->success == 0) goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &status);
    if (err < 0) goto error;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &status, sizeof(int *));
    goto out;

error:
    LOGE("%s error\n", __func__);
    RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, NULL, 0);
    //RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
out:

    LOGE("%s leave\n", __func__);

    free(cmd);
    at_response_free(p_response);
}

static void  requestSetFacility(void*  data, size_t  datalen, RIL_Token  t,int request)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    int remaining_times = -1;
    char *fac = NULL;
    char *mode = NULL;
    char *password = NULL;
    char *class = NULL;
    RIL_Errno errorril = RIL_E_SUCCESS;

    LOGE("%s Enter\n", __func__);

    fac = ((char **)data)[0];
    mode = ((char **)data)[1];
    password = ((char **)data)[2];
    class = ((char **)data)[3];

    asprintf(&cmd,"AT+CLCK=\"%s\",%s,\"%s\",%s",fac,mode,password,class);
    err = at_send_command(cmd,&p_response);
    free(cmd);
    //if(err < 0 || p_response == NULL || p_response->success == 0) goto error;

    if (err != 0) {
        switch (at_get_cme_error(p_response)) {
        /* CME ERROR 11: "SIM PIN required" happens when PIN is wrong */
        case CME_SIM_PIN_REQUIRED:
            LOGI("Wrong PIN");
            errorril = RIL_E_PASSWORD_INCORRECT;
            break;
        /*
         * CME ERROR 12: "SIM PUK required" happens when wrong PIN is used
         * 3 times in a row
         */
        case CME_SIM_PUK_REQUIRED:
            LOGI("PIN locked, change PIN with PUK");
            //num_retries = 0;/* PUK required */
            errorril = RIL_E_PASSWORD_INCORRECT;
            break;
        /* CME ERROR 16: "Incorrect password" happens when PIN is wrong */
        case CME_INCORRECT_PASSWORD:
            LOGI("Incorrect password, Facility");
            errorril = RIL_E_PASSWORD_INCORRECT;
            break;
        /* CME ERROR 17: "SIM PIN2 required" happens when PIN2 is wrong */
        case CME_SIM_PIN2_REQUIRED:
            LOGI("Wrong PIN2");
            errorril = RIL_E_PASSWORD_INCORRECT;
            break;
        /*
         * CME ERROR 18: "SIM PUK2 required" happens when wrong PIN2 is used
         * 3 times in a row
         */
        case CME_SIM_PUK2_REQUIRED:
            LOGI("PIN2 locked, change PIN2 with PUK2");
            //num_retries = 0;/* PUK2 required */
            errorril = RIL_E_SIM_PUK2;
            break;
        default: /* some other error */
            //num_retries = -1;
            errorril = RIL_E_GENERIC_FAILURE;
            break;
        }
    }
    
    remaining_times = getRemainingTimes(request);
    LOGI("remaining_times = %d",remaining_times);
    RIL_onRequestComplete(t, errorril, &remaining_times, sizeof(int *));
}

static void  requestChangeSimPin(void*  data, size_t  datalen, char *fac, RIL_Token  t,int request)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    int remaining_times = -1;
    char *oldpin = NULL,*newpin = NULL;

    LOGE("%s Enter\n", __func__);

    oldpin = ((char **)data)[0];
    newpin = ((char **)data)[1];

    asprintf(&cmd,"AT+CPWD=\"%s\",\"%s\",\"%s\"",fac,oldpin,newpin);
    err = at_send_command(cmd,&p_response);
    free(cmd);
    //if(err < 0 || p_response == NULL || p_response->success == 0) goto error;
    
    remaining_times = getRemainingTimes(request);
    LOGI("remaining_times = %d",remaining_times);
    //RIL_onRequestComplete(t, RIL_E_SUCCESS, &remaining_times, sizeof(int *));

    if(err < 0 || p_response == NULL || p_response->success == 0) {
        if (at_get_cme_error(p_response) == CME_INCORRECT_PASSWORD) {
            RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, &remaining_times, sizeof(int *));
        } else {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, &remaining_times, sizeof(int *));
        }
    } else {
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &remaining_times, sizeof(int *));
    }
}

static void  requestEnterSimPin(void*  data, size_t  datalen, RIL_Token  t,int request)
{
    ATResponse   *p_response = NULL;
    int           err;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    int remaining_times = -1;

    LOGE("%s Enter\n", __func__);

    if (( datalen == sizeof(char*)) || !strings[1] || !strings[1][0]) {
        asprintf(&cmd, "AT+CPIN=%s", strings[0]);
    } else {
        asprintf(&cmd, "AT+CPIN=\"%s\",\"%s\"", strings[0], strings[1]);
    }

    err = at_send_command(cmd, &p_response);
    free(cmd);
    //if(err < 0 || p_response == NULL || p_response->success == 0) goto error;

    remaining_times = getRemainingTimes(request);
    LOGI("remaining_times = %d",remaining_times);

    if(err < 0 || p_response == NULL || p_response->success == 0) {
        if (at_get_cme_error(p_response) == CME_INCORRECT_PASSWORD) {
            RIL_onRequestComplete(t, RIL_E_PASSWORD_INCORRECT, &remaining_times, sizeof(int *));
        } else {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, &remaining_times, sizeof(int *));
        }
    } else {
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &remaining_times, sizeof(int *));
    }    
}

static void  requestSendUSSD(void *data, size_t datalen, RIL_Token t)
{
    ATResponse   *p_response = NULL;
    int err;
    char *cmd = NULL;
    const char *ussdRequest;
    int mode,dcs;

#ifdef CUSD_USE_UCS2_MODE
	int i = 0;
	char ucs2[100];
	ussdRequest = (char *)(data);
	while (ussdRequest[i]) {
		sprintf(ucs2+i*4, "%04X", ussdRequest[i]);
		i++;
	}
	data = ucs2;
#endif
    ussdRequest = (char *)(data);
    mode = 1;
//    dcs = 15;

    //asprintf(&cmd,"AT+CUSD=%d,%s,%d",mode,ussdRequest,dcs);                                                                                              
    asprintf(&cmd,"AT+CUSD=%d,\"%s\"",mode,ussdRequest);                                                                                              
    err = at_send_command(cmd,&p_response);
    if(err != 0 || p_response == NULL || p_response->success == 0)
    {
        goto error;
    }

#if 1 //quectel
    ussd_pending_index++;
    RIL_requestTimedCallback(onUssdTimedCallback, (void *)ussd_pending_index, &ussd_timeout_timeval);
#endif
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    LOGE("[Joe]ERROR: %s failed",__func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
// @@@ TODO

}

/**
 *  Wythe:Add on 2013-04-02 for 4.0 ril
 *  Add new function to handle more requests.
 *  Must response to RIL.JAVA.
 */

/*
* Function: requestScreenState
* Purpose : handle the request when screen is on or off.
* Request : RIL_REQUEST_SCREEN_STATE
*/
static void requestScreenState(void *data, size_t datalen, RIL_Token t)
{
#if 1 //quectel
    if ((USB_HOST_SUSPEND_SUPPORT == 0) && (ql_is_UC20)) { //if the usb host donot support suspend
        if (((int *)data)[0]) {
            at_send_command("AT+QCFG=\"urc/ri/smsincoming\",\"pulse\",120", NULL);
            at_send_command("AT+QCFG=\"urc/delay\",0", NULL);
        } else {
            at_send_command("AT+QCFG=\"urc/ri/smsincoming\",\"pulse\",2000", NULL);
            at_send_command("AT+QCFG=\"urc/delay\",1", NULL);
        }
    }
#endif

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

/*
*   Function: requestBaseBandVersion
*   Purpose : return string of BaseBand version
*   Request : RIL_REQUEST_BASEBAND_VERSION
*/
static void requestBaseBandVersion(void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *atResponse = NULL;
    char *line;

    err = at_send_command_singleline("AT+CGMR", "\0", &atResponse);

    if(err != 0){
        LOGE("[Wythe]%s() Error Reading Base Band Version!",__func__);
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    line = atResponse->p_intermediates->line;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, line, sizeof(char *));
    
    at_response_free(atResponse);
}


/*
*   Function: requestGetIMEISV 
*   Purpose : return the IMEI SV(software version)
*   Request : RIL_REQUEST_GET_IMEISV
*/
static void requestGetIMEISV(RIL_Token t)
{
    requestBaseBandVersion(NULL, 0, t);
    //RIL_onRequestComplete(t, RIL_E_SUCCESS, (void *)00, sizeof(char *));
}

/**
 *  Function: requestSetPreferredNetworkType
 *  Purpose : Requests to set the preferred network type for searching and registering
 *            (CS/PS domain, RAT, and operation mode).
 *  Request : RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE
 */ 
static void requestSetPreferredNetworkType(void *data, size_t datalen, RIL_Token t)
{
    int rat,err;
    const char* nwscanmode;
    const char* nwscanseq = "AT+QCFG=\"nwscanseq\",0"; /* AUTO */
	
    assert (datalen >= sizeof(int *));
    rat = ((int *)data)[0];

    if (ql_is_GSM) { /* For 2G module, it only work in GSM */
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
        return;
    }

    switch (rat) {
        case PREF_NET_TYPE_GSM_ONLY:    /* GSM ONLY*/
            nwscanmode = "AT+QCFG=\"nwscanmode\",1";
        break;
        case PREF_NET_TYPE_WCDMA: /* WCDMA ONLY*/
            nwscanmode = "AT+QCFG=\"nwscanmode\",2";
        break;
        case PREF_NET_TYPE_GSM_WCDMA: /* GSM/WCDMA (WCDMA preferred) */
        default:
            nwscanmode = "AT+QCFG=\"nwscanmode\",0";
            nwscanseq = "AT+QCFG=\"nwscanseq\",2"; /* WCDMA prior to GSM */
        break; 
    }

    err = at_send_command(nwscanseq, NULL);
    if (err != 0) 
        goto error;
    err = at_send_command(nwscanmode, NULL);
    if (err != 0) 
        goto error;

    ql_nwscanmode = nwscanmode;
    ql_nwscanseq = nwscanseq;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
	
error:
    LOGE("ERROR: requestSetPreferredNetworkType() failed\n");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

/*
*   Function: requestReportSTKServiceIsRunning
*   Purpose :
*   Request : RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING
*/
static void requestReportSTKServiceIsRunning(RIL_Token t)
{
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

/* 
 * Function: requestDeactivateDefaultPDP
 * Purpose :
 * Request : RIL_REQUEST_DEACTIVATE_DATA_CALL
 */ 
static void requestDeactivateDefaultPDP(void *data, size_t datalen, RIL_Token t)
{
    char * cid;
    char *cmd;

    LOGD("requestDeactivateDefaultPDP()");

    if (!strncmp(PPP_TTY_PATH, "ppp", 3))
        ql_pppd_stop(SIGTERM);
    else
        ql_ndis_stop(SIGTERM);
    cid = ((char **)data)[0];
    asprintf(&cmd, "AT+CGACT=0,%s", cid);
#if 1 //it is not need to send this AT to deactive pdp, only to check pdp status
    at_send_command_multiline("AT+CGACT?", "+CGACT:", NULL);
#else
    at_send_command(cmd, NULL);
#endif

    free(cmd);
    
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;

error:
    LOGE("%s error\n",__func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

/**
 * Funtcion:requestLastPDPFailCause
 *
 * Purpose :Requests the failure cause code for the most recently failed PDP
 * context activate.
 *
 * Request : RIL_REQUEST_LAST_CALL_FAIL_CAUSE.
 *
 */
static int s_lastPdpFailCause = PDP_FAIL_ERROR_UNSPECIFIED;
static void requestLastPDPFailCause(RIL_Token t)
{
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &s_lastPdpFailCause, sizeof(int));
} 

static void requestGsmGetBroadcastSmsConfig(RIL_Token t) {
	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
}

static void requestGsmSetBroadcastSmsConfig(void *data, size_t datalen, RIL_Token t) {
	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
}

static void requestGsmSmsBroadcastActivation(void *data, size_t datalen, RIL_Token t) {
	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
}

static void requestDtmfStop(RIL_Token t) {
	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
}

static void requestQueryCallForwardStatus(void *data, size_t datalen, RIL_Token t)
{
    RIL_CallForwardInfo *callForwardInfo = (RIL_CallForwardInfo *)data;
    RIL_CallForwardInfo *r_callForwardInfo[10];
    char *cmd = NULL;
    int err;
    ATLine *tmp = NULL;
    char *line = NULL;
    ATResponse *atResponse;
    int i = 0;

    asprintf(&cmd,"AT+CCFC=%d,2",callForwardInfo->reason);
    err = at_send_command_multiline(cmd,"+CCFC:",&atResponse);
    free(cmd);
    if (err < 0 || atResponse->success == 0)
        goto error;

    tmp = atResponse->p_intermediates;
    while (tmp) 
    {
        r_callForwardInfo[i] = (RIL_CallForwardInfo *)alloca(sizeof(RIL_CallForwardInfo));
        bzero(r_callForwardInfo[i],sizeof(RIL_CallForwardInfo));
        r_callForwardInfo[i]->number = (char *)alloca(15);
        bzero(r_callForwardInfo[i]->number,15);
        line = tmp->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;
        err = at_tok_nextint(&line,&(r_callForwardInfo[i]->status));
        if (err < 0) goto error;
        if(r_callForwardInfo[i]->status != 0)
        {
            err = at_tok_nextint(&line,&(r_callForwardInfo[i]->serviceClass));
            if (err < 0) goto error;
            err = at_tok_nextstr(&line,&(r_callForwardInfo[i]->number));
            if (err < 0) goto error;
            LOGI("status:%d\nserviceClass:%d\nnumber:%s\n",r_callForwardInfo[i]->status,r_callForwardInfo[i]->serviceClass,r_callForwardInfo[i]->number);
        }
        i++;

        tmp = tmp->p_next;
    }

	RIL_onRequestComplete(t, RIL_E_SUCCESS, r_callForwardInfo, i * sizeof(RIL_CallForwardInfo *));
    return;
error:
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestSetCallForward(void *data, size_t datalen, RIL_Token t)
{
    char *cmd = NULL;
    int err;
    RIL_CallForwardInfo *callForwardInfo = (RIL_CallForwardInfo *)data;

    if(callForwardInfo->serviceClass == 0)
    {
        asprintf(&cmd,"AT+CCFC=%d,%d,\"%s\",%d",
                 callForwardInfo->reason,callForwardInfo->status,
                 callForwardInfo->number,callForwardInfo->toa);
    }
    else
    {
        asprintf(&cmd,"AT+CCFC=%d,%d,\"%s\",%d,%d",
                 callForwardInfo->reason,callForwardInfo->status,
                 callForwardInfo->number,callForwardInfo->toa,callForwardInfo->serviceClass);
    }

    err = at_send_command(cmd, NULL);
    free(cmd);
    if(err != 0) goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestGetClir(RIL_Token t)
{
    int err;
    int response[2];
    int n; 
    int m;
    char *line = NULL;
    ATResponse *atResponse = NULL;

    err = at_send_command_singleline("AT+CLIR?","+CLIR:",&atResponse);
	if (err != 0) goto error;
    
	line = atResponse->p_intermediates->line;
	err = at_tok_start(&line);
	if (err < 0) goto error;
    
    err = at_tok_nextint(&line,&n);
	if (err < 0) goto error;

    err = at_tok_nextint(&line,&m);
	if (err < 0) goto error;

    response[0] = n;
    response[1] = m;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    return ;

error:
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestSetClir(void *data, size_t datalen, RIL_Token t)
{
    int err;
    char *cmd = NULL;

    asprintf(&cmd, "AT+CLIR=%d",((int *)data)[0]);
    err = at_send_command(cmd,NULL);
	if (err != 0) goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    free(cmd);
    return ;

error:
    free(cmd);
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestQueryCallWaiting(void *data, size_t datalen, RIL_Token t)
{
    int err;
    char *cmd = NULL;
    int response[2];
    int status; 
    int class;
    char *line = NULL;
    ATResponse *atResponse = NULL;

    asprintf(&cmd, "AT+CCWA=1,2,%d",((int *)data)[0]);
    err = at_send_command_singleline(cmd,"+CCWA:",&atResponse);
	if (err != 0) goto error;
    
	line = atResponse->p_intermediates->line;
	err = at_tok_start(&line);
	if (err < 0) goto error;
    
    err = at_tok_nextint(&line,&status);
	if (err < 0) goto error;

    err = at_tok_nextint(&line,&class);
	if (err < 0) goto error;

    response[0] = status;
    response[1] = class;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    free(cmd);
    return ;

error:
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestSetCallWaiting(void *data, size_t datalen, RIL_Token t)
{
    int err;
    char *cmd = NULL;

    asprintf(&cmd, "AT+CCWA=1,%d,%d",((int *)data)[0],((int *)data)[1]);
    err = at_send_command(cmd,NULL);
	if (err != 0) goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    free(cmd);
    return ;

error:
    free(cmd);
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestDtmfStart(void *data, size_t datalen, RIL_Token t)
{
    int err;
    char *cmd;

    asprintf(&cmd,"AT+VTS=%c",((char *)data)[0]);

    err = at_send_command(cmd,NULL);
	if (err != 0) 
		goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return ;
error:
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestSetMute(void *data, size_t datalen, RIL_Token t)
{
	int err;
    char *cmd = NULL;
    
	assert (datalen >= sizeof(int *));

	/* mute */
    asprintf(&cmd, "AT+CMUT=%d", ((int*)data)[0]);
	err = at_send_command(cmd, NULL);
    
	if (err != 0) 
		goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
	return;

error:
	LOGE("ERROR: requestSetMute failed");
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestGetMute(RIL_Token t)
{
	int err;
	ATResponse *atResponse = NULL;
	int response[1];
	char *line;

	err = at_send_command_singleline("AT+CMUT?", "+CMUT:", &atResponse);

	if (err != 0)
		goto error;

	line = atResponse->p_intermediates->line;

	err = at_tok_start(&line);
	if (err < 0) goto error;

	err = at_tok_nextint(&line, &response[0]);
	if (err < 0) goto error;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
	at_response_free(atResponse);

	return;

error:
	LOGE("ERROR: requestGetMute failed");
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
	at_response_free(atResponse);
}

/**
 * Funtcion:requestResetRadio
 *
 * Purpose :reset module for JAVA
 *
 * Request : RIL_REQUEST_RESET_RADIO.
 *
 */
static void requestResetRadio(RIL_Token t)
{
	int err = 0;

	/* Reset MS */
	err = at_send_command("AT+QRST=1,0", NULL);
	if(err != 0)
		goto error;

    /* sleep 5s to wait for reboot */
    sleep(5);
		
	RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
	return;
	
error:
    LOGE("[%s]: error for qrst\n", __func__);
	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
	return;
}

//Add by wythe on 2013-9-27 ->start

/**
 * Function:request get preferred network type
 *
 * Purpose :Query the preferred network type (CS/PS domain, RAT, and operation mode)
 * for searching and registering.
 *
 * Request :RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE
 */ 
static void requestGetPreferredNetworkType(RIL_Token t)
{
	/*
	 * AT+QCFG="nwscanmode",0       AUTO,WCDMA preferred
	 * AT+QCFG="nwscanmode",1       GSM ONLY
	 * AT+QCFG="nwscanmode",2       WCDMA ONLY
	 */

	ATResponse *atResponse = NULL;
	int err;
	char *line;
	int ret;
	int response = PREF_NET_TYPE_GSM_WCDMA;

    if (ql_is_GSM) {/* For 2G module, it only work in GSM */
        response = PREF_NET_TYPE_GSM_ONLY;
        RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
        return;
    }

	err = at_send_command_singleline("AT+QCFG=\"nwscanmode\"", "+QCFG:", &atResponse);

	if (err != 0) {
		// assume radio is off
		goto error;
	}

	line = atResponse->p_intermediates->line;

	err = at_tok_start(&line);
	if (err < 0) goto error;

	err = skipComma(&line);
    if (err < 0) goto error;

	err = at_tok_nextint(&line, &ret);
	if (err < 0) goto error;

	/* Based on reported +QCFG: "nwscanmode" */
	if (ret == 1) {
		response = PREF_NET_TYPE_GSM_ONLY;  /* GSM only */
	} else if (ret == 2) {
		response = PREF_NET_TYPE_WCDMA; /* WCDMA only */
	} else {
		response = PREF_NET_TYPE_GSM_WCDMA; /* for 3G Preferred */
	}
	
	D("requestGetPreferredNetworkType() mode:%d\n",response);
	RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
	at_response_free(atResponse);	
	return;
	
error:
	LOGE("ERROR: requestGetPreferredNetworkType() failed - modem does not support command\n");
	RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
	at_response_free(atResponse);
}
//Add by wythe on 2013-9-27 ->end

struct operatorPollParams {
    RIL_Token t;
    int loopcount;
}; 


#define REPOLL_OPERATOR_SELECTED 30     
static const struct timeval TIMEVAL_OPERATOR_SELECT_POLL = { 2, 0 }; 

/**
 * Poll +COPS? and return a success, or if the loop counter reaches
 * REPOLL_OPERATOR_SELECTED, return generic failure.
 */
static void pollOperatorSelected(void *params)
{
    int err = 0;
    int response = 0;
    char *line = NULL;
    ATResponse *atResponse = NULL;
    struct operatorPollParams *poll_params;
    RIL_Token t;

    assert(params != NULL);

    poll_params = (struct operatorPollParams *) params;
    t = poll_params->t;

    if (poll_params->loopcount >= REPOLL_OPERATOR_SELECTED)
        goto error;

    err = at_send_command_singleline("AT+COPS?", "+COPS:", &atResponse);
    if (err != 0)
        goto error;

    line = atResponse->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    err = at_tok_nextint(&line, &response);
    if (err < 0)
        goto error;

    /* If we don't get more than the COPS: {0-4} we are not registered.
       Loop and try again. */
    if (!at_tok_hasmore(&line)) {
            poll_params->loopcount++;
            RIL_requestTimedCallback(pollOperatorSelected,
                            poll_params, &TIMEVAL_OPERATOR_SELECT_POLL);
    } else {
        /* We got operator, throw a success! */
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
        free(poll_params);
    }

    at_response_free(atResponse);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    free(poll_params);
    at_response_free(atResponse);
    return;
}

/**
 *  Add handler for RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC
 *  wythe add on 2014-3-28
 */
void requestSetNetworkSelectionAutomatic(RIL_Token t)
{
    int err = 0;
    ATResponse *atResponse = NULL;
    int mode = 0;
    int skip;
    char *line;
    char *netOperator = NULL;
    struct operatorPollParams *poll_params = NULL;

    poll_params = (struct operatorPollParams*)
					malloc(sizeof(struct operatorPollParams));
    if (NULL == poll_params)
        goto error;

    /* First check if we are already scanning or in manual mode */
    err = at_send_command_singleline("AT+COPS=3,2;+COPS?", "+COPS:", &atResponse);
    if (err != 0)
        goto error;

    line = atResponse->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    /* Read network selection mode */
    err = at_tok_nextint(&line, &mode);
    if (err < 0)
        goto error;

    /* If we're unregistered, we may just get
       a "+COPS: 0" response. */
    if (!at_tok_hasmore(&line)) {
        if (mode == 1) {
            LOGD("%s() Changing manual to automatic network mode", __func__);
            goto do_auto;
        } else
            goto check_reg;
    }

    err = at_tok_nextint(&line, &skip);
    if (err < 0)
        goto error;

    /* A "+COPS: 0, n" response is also possible. */
    if (!at_tok_hasmore(&line)) {
        if (mode == 1) {
            LOGD("%s() Changing manual to automatic network mode", __func__);
            goto do_auto;
        } else
            goto check_reg;
    }

    /* Read numeric operator */
    err = at_tok_nextstr(&line, &netOperator);
    if (err < 0)
        goto error;

    /* If operator is found then do a new scan,
       else let it continue the already pending scan */
    if (netOperator && strlen(netOperator) == 0) {
        if (mode == 1) {
            LOGD("%s() Changing manual to automatic network mode", __func__);
            goto do_auto;
        } else
            goto check_reg;
    }

    /* Operator found */
    if (mode == 1) {
        LOGD("%s() Changing manual to automatic network mode", __func__);
        goto do_auto;
    } else {
        LOGD("%s() Already in automatic mode with known operator, trigger a new network scan",
	    __func__);
        goto do_auto;
    }

    /* Check if module is scanning,
       if not then trigger a rescan */
check_reg:
    at_response_free(atResponse);
    atResponse = NULL;

    /* Check CS domain first */
    err = at_send_command_singleline("AT+CREG?", "+CREG:", &atResponse);
    if (err != 0)
        goto error;

    line = atResponse->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    /* Read registration unsolicited mode */
    err = at_tok_nextint(&line, &mode);
    if (err < 0)
        goto error;

    /* Read registration status */
    err = at_tok_nextint(&line, &mode);
    if (err < 0)
        goto error;

    /* If scanning has stopped, then perform a new scan */
    if (mode == 0) {
        LOGD("%s() Already in automatic mode, but not currently scanning on CS,"
	     "trigger a new network scan", __func__);
        goto do_auto;
    }

    /* Now check PS domain */
    at_response_free(atResponse);
    atResponse = NULL;
    err = at_send_command_singleline("AT+CGREG?", "+CGREG:", &atResponse);
    if (err != 0)
        goto error;

    line = atResponse->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0)
        goto error;

    /* Read registration unsolicited mode */
    err = at_tok_nextint(&line, &mode);
    if (err < 0)
        goto error;

    /* Read registration status */
    err = at_tok_nextint(&line, &mode);
    if (err < 0)
        goto error;

    /* If scanning has stopped, then perform a new scan */
    if (mode == 0) {
        LOGD("%s() Already in automatic mode, but not currently scanning on PS,"
	     "trigger a new network scan", __func__);
        goto do_auto;
    }
    else
    {
        LOGD("%s() Already in automatic mode and scanning", __func__);
        goto finish_scan;
    }

do_auto:
    at_response_free(atResponse);
    atResponse = NULL;

    /* This command does two things, one it sets automatic mode,
       two it starts a new network scan! */
    err = at_send_command("AT+COPS=0", NULL);
    if (err != 0)
        goto error;
    if (ql_nwscanseq && ql_nwscanmode) {
        at_send_command(ql_nwscanseq, NULL);
        at_send_command(ql_nwscanmode, NULL);
    }

finish_scan:

    at_response_free(atResponse);
    atResponse = NULL;

    poll_params->loopcount = 0;
    poll_params->t = t;

    RIL_requestTimedCallback(pollOperatorSelected,
                    poll_params, &TIMEVAL_OPERATOR_SELECT_POLL);

    return;

error:
    free(poll_params);
    at_response_free(atResponse);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    return;    
}

/**
 *  Add handler for RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL
 *  wythe add on 2014-3-28
 *  Set the network selection manually.
 */
void requestSetNetworkSelectionManual(void *data, size_t datalen,
                                      RIL_Token t)
{
    /*
     * AT+COPS=[<mode>[,<format>[,<oper>[,<AcT>]]]]
     *    <mode>   = 4 = Manual (<oper> field shall be present and AcT optionally) with fallback to automatic if manual fails.
     *    <format> = 2 = Numeric <oper>, the number has structure:
     *                   (country code digit 3)(country code digit 2)(country code digit 1)
     *                   (network code digit 2)(network code digit 1)
     */

    (void) datalen;
    int err = 0;
		char *cmd = NULL;
    const char *mccMnc = (const char *) data;

    /* Check inparameter. */
    if (mccMnc == NULL)
        goto error;

    /* Build and send command. */
    asprintf(&cmd, "AT+COPS=1,2,\"%s\"", mccMnc);
    err = at_send_command(cmd, NULL);
    if (err != 0) {
        err = at_send_command("AT+COPS=0",NULL);
        if(err != 0) 
            goto error;
        if (ql_nwscanseq && ql_nwscanmode) {
            at_send_command(ql_nwscanseq, NULL);
            at_send_command(ql_nwscanmode, NULL);
        }
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

/**
 *  Add handler for RIL_REQUEST_QUERY_AVAILABLE_NETWORKS
 *  Wythe 2014-3-28 -> start
 *  Query available network to system. It may takes long
 *  time to scan BaseStation around.
 */
static void requestQueryAvailableNetworks(RIL_Token t)
{
    /**
     * AT+COPS=?
     *   +COPS:[(list of supported<stat>,
     *          long alphanumeric <oper>,
                short alphanumeric <oper>,
                numeric <oper>s[,<Act>]s)]
                [,,(list supported <mode>s),(list of supported <format>s)]
     *
     * <stat>   0   Unknown
     *          1   Operator available
     *          2   Operator current
     *          3   Operator forbidden
     */

    /**
     * long alphanumeric
     * short alphanumeric
     * numeric
     * stat
     */
    #define QUERY_AVAILABLE_NW_PARAMS_NUM   4

    const char *statusTable[]=
    {"unknown", "available", "current", "forbidden"};

    ATResponse *atResponse = NULL;
    int err = 0;
    char *line = NULL;
    int n = 0;
    char **responseArray = NULL;
    int i = 0;

    err = at_send_command_singleline("AT+COPS=?", "+COPS", &atResponse);

    if(err != 0 || atResponse->p_intermediates == NULL){
    		LOGE("%s:%s It's error when querying the available network\n", __func__, line);
		    goto error;
		}

    line = atResponse->p_intermediates->line;

    if(line == NULL)
        goto error;

    LOGD("%s:Read COPS response = %s\n", __func__, line);

    err = at_tok_start(&line);
    if(err < 0) goto error;

    err = at_tok_charcounter(line, "(", &n);
    if(err < 0) goto error;

    //Do not need (list supported <mode>s), (list supported <format>s) here
    if(n < 2) n = 0;
    else n -= 2;

		LOGD("%s:Get %d operator information from modem", __func__, n);

    responseArray = (char **)alloca(n * QUERY_AVAILABLE_NW_PARAMS_NUM * sizeof(char *));
		if(NULL == responseArray) goto error;

    for(i = 0; i < n; i++)
    {
        char *s = NULL;
        char *p_line = NULL;
        char *remaining = NULL;
        char *long_alphanumeric = NULL;
        char *short_alphanumeric = NULL;
        char *numeric = NULL;
        int status = 0;
				int act = 0;

        //get the content in (), like ("CHN-UNICOM")
        s = p_line = at_tok_getElementValue(line, "(", ")", &remaining);
        line = remaining;

        if(p_line == NULL)
        {
            LOGE("ERROR:%s NULL pointer while parsing COPS response\n", __func__);
            break;
        }

        //stat <oper>
        err = at_tok_nextint(&p_line, &status);
        if(err < 0) 
        {
error_response:
            free(s);
            goto error;
        }
				
#if 0
				// If the operator's status is unknown or forbidden, don't pass it to RIL java.
				if(0 == status || 3 == status)
				{
						free(s);
						continue;
				}
#endif   
        //long alphanumeric <oper>
        err = at_tok_nextstr(&p_line, &long_alphanumeric);
        if(err < 0) goto error_response;

        //short alphanumeric <oper>
        err = at_tok_nextstr(&p_line, &short_alphanumeric);
        if(err < 0) goto error_response;

        //numeric <oper>
        err = at_tok_nextstr(&p_line, &numeric);
        if(err < 0) goto error_response;

				// Act <oper>
				err = at_tok_nextint(&p_line, &act);
        if(err < 0) {
            if (ql_is_GSM) /* For 2G module, it only work in GSM */
               act = 0;
            else
                goto error_response;
        }

        //add long alphanumeric in array[0]
        responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 0] = (char *)alloca(strlen(long_alphanumeric)+1);
        strcpy(responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 0], long_alphanumeric);

        //add short alphanumeric in array[1]
        responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 1] = (char *)alloca(strlen(short_alphanumeric)+1);
        strcpy(responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 1], short_alphanumeric);

        //add numeric in array[2]
        responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 2] = (char *)alloca(strlen(numeric)+1);
        strcpy(responseArray[i*QUERY_AVAILABLE_NW_PARAMS_NUM + 2], numeric);

        free(s);
        
        /**
         *  If module responds empty sring for long alphanumeric and short alphanumeric,
         *  then we copy the MNC/MMC to them.
         */
        
        if (responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 0] && strlen(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 0]) == 0) {
            responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 0] = (char*) alloca(strlen(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 2]) + 1);
            strcpy(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 0], responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 2]);
        }

        if (responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 1] && strlen(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 1]) == 0) {
            responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 1] = (char*) alloca(strlen(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 2]) + 1);
            strcpy(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 1], responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 2]);
        }

				//add status in array[3]
        responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 3] = (char*) alloca(strlen(statusTable[status])+1);
				strcpy(responseArray[i * QUERY_AVAILABLE_NW_PARAMS_NUM + 3],statusTable[status]);
    }
    
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseArray, i * QUERY_AVAILABLE_NW_PARAMS_NUM * sizeof(char *));

finally:
    at_response_free(atResponse);
    return;
    
error:
    LOGE("ERROR:requestQueryAvailableNetworks() get no response form module\n");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
	goto finally;
}

/**
 *  Wythe 2014-3-28 -> end
 */

#define MAX_NUM_NEIGHBOR_CELLS 10

void requestGetNeighboringCellIDs(RIL_Token t)
{
    int err = 0;
    char *p = NULL;
    int n = 0;
    ATLine *tmp = NULL;
    ATResponse *atresponse = NULL;
    RIL_NeighboringCell *ptr_cells[MAX_NUM_NEIGHBOR_CELLS];

    err = at_send_command_multiline("AT+QENG=\"neighbourcell\"", "+QENG:", &atresponse);
    if (err < 0 || atresponse->success == 0)
        goto error;

    tmp = atresponse->p_intermediates;
    while (tmp) 
    {
        if (n > MAX_NUM_NEIGHBOR_CELLS)
            goto error;
        p = tmp->line;
        {
            char *line = p;
            int lac = 0;
            int cellid = 0;
            int rssi = 0;
            int psc = 0;
            //int pathloss = 0;
            char *net_type;
            char *tmp_str;
            int tmp_int;

            err = at_tok_start(&line);
            if (err < 0)
                goto error;

            /* neighbourcell */
            err = at_tok_nextstr(&line, &tmp_str);
            if (err < 0)
                goto error;

            /* 3G/2G */
            err = at_tok_nextstr(&line, &net_type);
            if (err < 0)
                goto error;

            /* mmc */
            err = at_tok_nextint(&line, &tmp_int);
            if (err < 0)
            {
                LOGE("get mmc error");
                goto next;
            }

            /* mnc */
            err = at_tok_nextint(&line, &tmp_int);
            if (err < 0)
            {
                LOGE("get mnc error");
                goto next;
            }

            /* lac */
            //err = at_tok_nextint(&line, &lac);
            err = at_tok_nexthexint(&line, &lac);
            if (err < 0)
            {
                LOGE("get lac error");
                goto next;
            }

            /* cellid */
            //err = at_tok_nextint(&line, &cellid);
            err = at_tok_nexthexint(&line, &cellid);
            if (err < 0)
            {
                LOGE("get cellid error");
                goto next;
            }

            /* bsic/uarfcn */
            err = at_tok_nextint(&line, &tmp_int);
            if (err < 0)
            {
                LOGE("get bsic/uarfcn error");
                goto next;
            }

            /* psc/arfcn */
            err = at_tok_nextint(&line, &psc);
            if (err < 0)
            {
                LOGE("get psc/arfcn error");
                goto next;
            }

            /* rscp/rxlev */
            err = at_tok_nextint(&line, &rssi);
            if (err < 0)
            {
                LOGE("get rscp/rxlev error");
                goto next;
            }

            /* process data for each cell */
            ptr_cells[n] = alloca(sizeof(RIL_NeighboringCell));
            ptr_cells[n]->rssi = rssi;
            ptr_cells[n]->cid = alloca(9 * sizeof(char));
            if(!strncmp(net_type,"3G",2))
                sprintf(ptr_cells[n]->cid, "%08x", psc);
            else //2G
                sprintf(ptr_cells[n]->cid, "%08x", ((lac << 16) + cellid));
            LOGI("CID:%s  RSSI:%d",ptr_cells[n]->cid,ptr_cells[n]->rssi);
            n++;
        }
next:
        tmp = tmp->p_next;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, ptr_cells,n * sizeof(RIL_NeighboringCell *));

finally:
        at_response_free(atresponse);
    return;

error:
    LOGE("%s error",__func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    goto finally;
}


#ifdef RIL_REQUEST_GET_HARDWARE_CONFIG
static void requestGetHardwareConfig(void *data, size_t datalen, RIL_Token t)
{
#if 1
   RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
#else
   // TODO - hook this up with real query/info from radio.

   RIL_HardwareConfig hwCfg;

   RIL_UNUSED_PARM(data);
   RIL_UNUSED_PARM(datalen);

   hwCfg.type = -1;

   RIL_onRequestComplete(t, RIL_E_SUCCESS, &hwCfg, sizeof(hwCfg));
#endif
}
#endif

#ifdef RIL_REQUEST_GET_HARDWARE_CONFIG
static void requestShutdown(RIL_Token t)
{
    int onOff;

    int err;
    ATResponse *p_response = NULL;

    if (sState != RADIO_STATE_OFF) {
        err = at_send_command("AT+CFUN=0", &p_response);
        setRadioState(RADIO_STATE_UNAVAILABLE);
    }

    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
}
#endif

#ifdef RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE
static void requestSetCellInfoListRate(void *data, size_t datalen, RIL_Token t)
{
    // For now we'll save the rate but no RIL_UNSOL_CELL_INFO_LIST messages
    // will be sent.
    assert (datalen == sizeof(int));
    //s_cell_info_rate_ms = ((int *)data)[0];

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}
#endif


/*** Callback methods from the RIL library to us ***/

/**
 * Call from RIL to us to make a RIL_REQUEST
 *
 * Must be completed with a call to RIL_onRequestComplete()
 *
 * RIL_onRequestComplete() may be called from any thread, before or after
 * this function returns.
 *
 * Will always be called from the same thread, so returning here implies
 * that the radio is ready to process another command (whether or not
 * the previous command has completed).
 */
static void
onRequest (int request, void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response;
    int err;

    LOGD("onRequest: %s", requestToString(request));

#if 1 //quectel  //frameworks\base\telephony\java\com\android\internal\telephony/RIL.java ->processUnsolicited()
    onRequestCount++;
#endif

    switch (request) {

        /**** call ****/
        //--------------------------------------------------------
        case RIL_REQUEST_GET_CURRENT_CALLS:
            if (currentState() <= RADIO_STATE_UNAVAILABLE) {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                break;
            }
            requestGetCurrentCalls(data, datalen, t);
            break;
            
        case RIL_REQUEST_DIAL:
            requestDial(data, datalen, t);
            break;
            
        case RIL_REQUEST_HANGUP:
            requestHangup(data, datalen, t);
            break;
            
        case RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND:
            at_send_command("AT+CHLD=0", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND:
            at_send_command("AT+CHLD=1", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE:
            at_send_command("AT+CHLD=2", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_ANSWER:
            at_send_command("ATA", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_CONFERENCE:
            at_send_command("AT+CHLD=3", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_UDUB:
            at_send_command("ATH", NULL);

            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;

        case RIL_REQUEST_SEPARATE_CONNECTION:
            {
                char  cmd[12];
                int   party = ((int*)data)[0];

                if (party > 0 && party < 10) {
                    sprintf(cmd, "AT+CHLD=2%d", party);
                    at_send_command(cmd, NULL);
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                } else {
                    LOGD("%s error for RIL_REQUEST_SEPARATE_CONNECTION!\n", __func__);
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                }
            }
            break;
        //--------------------------------------------------------    

        /**** sms ****/
        //--------------------------------------------------------
        case RIL_REQUEST_SEND_SMS:
            requestSendSMS(data, datalen, t);
            break;

        case RIL_REQUEST_SEND_SMS_EXPECT_MORE:
            requestSendSMSExpectMore(data, datalen, t);
            break;

        case RIL_REQUEST_SMS_ACKNOWLEDGE:
            requestSMSAcknowledge(data, datalen, t);
            break;

        case RIL_REQUEST_WRITE_SMS_TO_SIM:
            requestWriteSmsToSim(data, datalen, t);
            break;

        case RIL_REQUEST_DELETE_SMS_ON_SIM: {
            char * cmd;
            p_response = NULL;
            asprintf(&cmd, "AT+CMGD=%d", ((int *)data)[0] - 1);
            err = at_send_command(cmd, &p_response);
            free(cmd);
            if (err < 0 || p_response->success == 0) {
                LOGE("%s error for RIL_REQUEST_DELETE_SMS_ON_SIM!\n", __func__);
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            at_response_free(p_response);
            break;
        }
        //--------------------------------------------------------

        /**** data connection ****/
        //--------------------------------------------------------
        case RIL_REQUEST_DEACTIVATE_DATA_CALL: {
            requestDeactivateDefaultPDP(data, datalen, t);
            break;
        }

        case RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE: {
            requestLastPDPFailCause(t);
            break;
        }

        case RIL_REQUEST_SETUP_DATA_CALL:
            requestSetupDataCall(data, datalen, t);
            break;

        case RIL_REQUEST_DATA_CALL_LIST:
            requestDataCallList(data, datalen, t);
            break;
        //--------------------------------------------------------    

        /**** network ****/
        //--------------------------------------------------------
        case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:
            if (currentState() <= RADIO_STATE_UNAVAILABLE) {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                break;
            }            
            if (ql_is_UC20 || ql_is_GSM)
                requestSetPreferredNetworkType(data,datalen,t);
            else
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            break;

        case RIL_REQUEST_SIGNAL_STRENGTH:
            requestSignalStrength(data, datalen, t);
            break;
            
        case RIL_REQUEST_VOICE_REGISTRATION_STATE:
        case RIL_REQUEST_DATA_REGISTRATION_STATE:
            if (currentState() != RADIO_STATE_SIM_READY) {
                char * response[] = {"0"}; //Not registered
                RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
                break;
            }  
            requestRegistrationState(request, data, datalen, t);
            break;
            
        case RIL_REQUEST_OPERATOR:
            if (currentState() != RADIO_STATE_SIM_READY) {
                char *response[] = {NULL, NULL, NULL};
                RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response)); 
                break;
            } 
            requestOperator(data, datalen, t);
            break;

				/***
				 *	Drop.
				 *	wythe 2014-3-28 
				 */
#if 0
        case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
            at_send_command("AT+COPS=0", NULL);
            break;
#endif

        case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE:
            if (currentState() != RADIO_STATE_SIM_READY) {
                int response[] = {0};
                RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response)); 
                break;
            } 
            requestQueryNetworkSelectionMode(data, datalen, t);
            break;

        /**
         *  Add new request:RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE
         *  Wythe 2013-9-27
         */
        case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:
        if (ql_is_UC20 || ql_is_GSM)
            requestGetPreferredNetworkType(t);
        else
            	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
         break;

        /**
         *  Add new request:RIL_REQUEST_QUERY_AVAILABLE_NETWORKS
         *  Wythe 2014-3-28
         */
        case RIL_REQUEST_QUERY_AVAILABLE_NETWORKS:
            requestQueryAvailableNetworks(t);
            break;

        /**
         *  Add new request:RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL
         *  Wythe 2014-3-28
         */
        case RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL:
            requestSetNetworkSelectionManual(data, datalen, t);
            break;

        /**
         *  Add new request:RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC
         *  Wythe 2014-3-28
         *
         */
        case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
            requestSetNetworkSelectionAutomatic(t);
            break;
            
        //--------------------------------------------------------    

        /**** sim card ****/
        //--------------------------------------------------------
        case RIL_REQUEST_GET_SIM_STATUS: {
            RIL_CardStatus_v6 *p_card_status;
            char *p_buffer;
            int buffer_size;

            int result = getCardStatus(&p_card_status);
            if (result == RIL_E_SUCCESS) {
                p_buffer = (char *)p_card_status;
                buffer_size = sizeof(*p_card_status);
            } else {
                p_buffer = NULL;
                buffer_size = 0;
            }
            RIL_onRequestComplete(t, result, p_buffer, buffer_size);
            freeCardStatus(p_card_status);
            break;
        }

         case RIL_REQUEST_GET_IMSI:
            p_response = NULL;
            err = at_send_command_numeric("AT+CIMI", &p_response);

            if (err < 0 || p_response->success == 0) {
                LOGE("%s error for RIL_REQUEST_GET_IMSI!\n", __func__);
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS,
                    p_response->p_intermediates->line, sizeof(char *));
            }
            at_response_free(p_response);
            break;

         case RIL_REQUEST_SIM_IO:
            requestSIM_IO(data,datalen,t);
            break;

        case RIL_REQUEST_QUERY_FACILITY_LOCK:
            requestQuestFacility(data,datalen,t);
            break;

        case RIL_REQUEST_SET_FACILITY_LOCK:
            requestSetFacility(data,datalen,t,request);
            break;

        case RIL_REQUEST_CHANGE_SIM_PIN:
            requestChangeSimPin(data,datalen,"SC",t,request);
            break;

        case RIL_REQUEST_CHANGE_SIM_PIN2:
            requestChangeSimPin(data,datalen,"P2",t,request);
            break;

        case RIL_REQUEST_ENTER_SIM_PIN:
        case RIL_REQUEST_ENTER_SIM_PUK:
        case RIL_REQUEST_ENTER_SIM_PIN2:
        case RIL_REQUEST_ENTER_SIM_PUK2:
            requestEnterSimPin(data, datalen, t,request);
            break;
        //--------------------------------------------------------    
            
        /**** other,e.g. system, baseband information****/
        case RIL_REQUEST_SCREEN_STATE: {
            if (currentState() != RADIO_STATE_SIM_READY) {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                break;
            }   
            requestScreenState(data,datalen,t);
            break;
        }

        case RIL_REQUEST_BASEBAND_VERSION: {
            requestBaseBandVersion(data,datalen,t);
            break;
        }

        case RIL_REQUEST_GET_IMEISV: {
            requestGetIMEISV(t);
            break;
        }
       
        case RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING: {
            requestReportSTKServiceIsRunning(t);
            break;
        }

        case RIL_REQUEST_RADIO_POWER:
#if 1 //quectel  //frameworks\base\telephony\java\com\android\internal\telephony/RIL.java ->processUnsolicited()
//case RIL_UNSOL_RIL_CONNECTED : setRadioPower(false, null);
//it it no need to power off radio when RIL.java connect
        if ((onRequestCount < 4) && (((int *)data)[0] == 0)) {
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        }
#endif
            requestRadioPower(data, datalen, t);
            break;
        case RIL_REQUEST_DTMF: {
            char c = ((char *)data)[0];
            char *cmd;
            asprintf(&cmd, "AT+VTS=%c", (int)c);
            at_send_command(cmd, NULL);
            free(cmd);
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        }

        case RIL_REQUEST_GET_IMEI:
            if (ql_is_EC20) { //EC20 bug, canot get OK
                //RIL_onRequestComplete(t, RIL_E_SUCCESS, "355189036244202", sizeof(char *));
                //return;
            }
            p_response = NULL;
            err = at_send_command_numeric("AT+CGSN", &p_response);

            if (err < 0 || p_response->success == 0) {
                LOGE("%s error for RIL_REQUEST_GET_IMEI!\n", __func__);
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS,
                    p_response->p_intermediates->line, sizeof(char *));
            }
            at_response_free(p_response);
            break;

        case RIL_REQUEST_SEND_USSD:
            requestSendUSSD(data, datalen, t);
            break;

        case RIL_REQUEST_CANCEL_USSD:
#if 1 //quectel
            ussd_pending_index++;
#endif
            at_send_command("AT+CUSD=2", NULL);
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;

        case RIL_REQUEST_OEM_HOOK_RAW:
            // echo back data
            RIL_onRequestComplete(t, RIL_E_SUCCESS, data, datalen);
            break;

        case RIL_REQUEST_SET_BAND_MODE:
            if (ql_is_UC20) {
                ATResponse *atResponse = NULL;
                int err;
                int bandval = 0;
                char *cmd;
                
                switch(((int *)data)[0])
                {
                    case 1:
                        bandval = 3;
                        break;
                    case 2:
                        bandval = 108;
                        break;
                    case 3:
                        bandval = 256;
                        break;
                    case 4:
                    case 5:
                        bandval = 67;
                        break;
                    default:
                        bandval = 512;
                }
                asprintf(&cmd,"AT+QCFG=\"band\",%d",bandval);
                err = at_send_command(cmd,&atResponse);

                if(err < 0 || atResponse == NULL || atResponse->success == 0)
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                else
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                free(atResponse);
                free(cmd);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_QUERY_AVAILABLE_BAND_MODE:
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            break;

        case RIL_REQUEST_GET_SMSC_ADDRESS:
            {
                ATResponse *p_response = NULL;
                char *cmd = NULL; 
                char *SMSC_address = NULL;
                int err;

                err = at_send_command_singleline("AT+CSCA?","+CSCA:",&p_response);
                if(err < 0 || p_response == NULL || p_response->success == 0)
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                else
                {
                    char *line;
#ifdef CUSD_USE_UCS2_MODE
                    unsigned char char_addr[128] = {0};
                    unsigned char ucs2[64];
#endif

                    line = p_response->p_intermediates->line;
                    err = at_tok_start(&line);
                    err = at_tok_nextstr(&line,&SMSC_address);
#ifdef CUSD_USE_UCS2_MODE
                    ucs2_to_utf8(ucs2, hexStringToBytes(SMSC_address, ucs2) / 2, char_addr);
                    SMSC_address = (char *)char_addr;
#endif

                    RIL_onRequestComplete(t, RIL_E_SUCCESS, SMSC_address, sizeof(char *));
                }
                free(p_response);
                free(cmd);
            }
            break;

        case RIL_REQUEST_SET_SMSC_ADDRESS:
            {
                ATResponse *p_response = NULL;
                char *cmd = NULL; 
                char *SMSC_address = NULL;
                int err;
#ifdef CUSD_USE_UCS2_MODE
                char ucs2_addr[128] = {0};
                const char bytesToHexString[] = "0123456789abcdef";
                size_t i;
                for (i = 0; i < strlen((char *)data); i++) {
                    ucs2_addr[i*4 + 0] =  '0';
                    ucs2_addr[i*4 + 1] =  '0';
                    ucs2_addr[i*4 + 2] =  bytesToHexString[((char *)data)[i] >> 4];
                    ucs2_addr[i*4 + 3] =  bytesToHexString[((char *)data)[i] & 0xf];
                }  
                data = ucs2_addr;
#endif
                
                SMSC_address = data;
                asprintf(&cmd,"AT+CSCA=\"%s\"",SMSC_address);

                err = at_send_command(cmd,&p_response);
                if(err < 0 || p_response == NULL || p_response->success == 0)
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                else
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);

                free(p_response);
                free(cmd);
            }
            break;


        case RIL_REQUEST_OEM_HOOK_STRINGS: {
            int i;
            const char ** cur;

            LOGD("got OEM_HOOK_STRINGS: 0x%8p %lu", data, (long)datalen);


            for (i = (datalen / sizeof (char *)), cur = (const char **)data ;
                    i > 0 ; cur++, i --) {
                LOGD("> '%s'", *cur);
            }

#if 1 //quectel
{
        int err;
        ATResponse *p_response = NULL;
        err = at_send_command_multiline( ((const char **)data)[0], "\0", &p_response);
        if(err < 0 || p_response == NULL || p_response->success == 0)
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        else
        {
            char *lines[100] ;
            size_t i = 0;
            ATLine  *p_intermediates = p_response->p_intermediates;
            while (p_intermediates && (i < ((sizeof(lines) / sizeof(lines[0])) - 1))) {
                if (p_intermediates->line)
                    lines[i++] = p_intermediates->line;
                p_intermediates = p_intermediates->p_next;
            }
            if (p_response->finalResponse)
                lines[i++] = p_response->finalResponse;
            RIL_onRequestComplete(t, RIL_E_SUCCESS, lines, i*sizeof(char *));
        }
}
#else
            // echo back strings
            RIL_onRequestComplete(t, RIL_E_SUCCESS, data, datalen);
#endif
            break;
        }

        case RIL_REQUEST_GSM_SET_BROADCAST_SMS_CONFIG: {
            requestGsmSetBroadcastSmsConfig(data, datalen, t);
            break;
        }

        case RIL_REQUEST_GSM_GET_BROADCAST_SMS_CONFIG: {
            requestGsmGetBroadcastSmsConfig(t);
            break;
        }

        case RIL_REQUEST_GSM_SMS_BROADCAST_ACTIVATION: {
            requestGsmSmsBroadcastActivation(data, datalen, t);
            break;
        }

        case RIL_REQUEST_RESET_RADIO: {
        if (ql_is_UC20)            
            requestResetRadio(t);
        else
            	RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            break;
        }

        case RIL_REQUEST_GET_MUTE: {
            requestGetMute(t);
            break;
        }

        case RIL_REQUEST_SET_MUTE: {
            requestSetMute(data, datalen, t);
            break;
        }

        case RIL_REQUEST_DTMF_START: {
            requestDtmfStart(data, datalen, t);
            break;
        }

        case RIL_REQUEST_DTMF_STOP: {
            requestDtmfStop(t);
            break;
        }

        case RIL_REQUEST_QUERY_CALL_FORWARD_STATUS: {
            requestQueryCallForwardStatus(data, datalen, t);
            break;
        }

        case RIL_REQUEST_SET_CALL_FORWARD: {
            requestSetCallForward(data, datalen, t);
            break;
        }

        case RIL_REQUEST_GET_CLIR: {
            requestGetClir(t);
            break;
        }

        case RIL_REQUEST_SET_CLIR: {
            requestSetClir(data, datalen, t);
            break;
        }

        case RIL_REQUEST_QUERY_CALL_WAITING: {
            requestQueryCallWaiting(data, datalen, t);
            break;
        }

        case RIL_REQUEST_SET_CALL_WAITING: {
            requestSetCallWaiting(data, datalen, t);
            break;
        }
#if 0
        case RIL_REQUEST_QUERY_AVAILABLE_NETWORKS:
            requestQueryAvailableNetworks(t);
            break;

        case RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL:
            requestSetNetworkSelectionManual(data, datalen, t);
            break;

        case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
            requestSetNetworkSelectionAutomatic(t);
            break;
#endif
        case RIL_REQUEST_GET_NEIGHBORING_CELL_IDS:
        if (ql_is_UC20)
            requestGetNeighboringCellIDs(t);
        else
              RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);          
            break;

#ifdef RIL_REQUEST_QUECTEL_AT
        case RIL_REQUEST_QUECTEL_AT: {
		ATResponse *p_response = NULL;
		int err = at_send_command((const char *)data,&p_response);
		//if(err < 0 || p_response == NULL || p_response->success == 0)
		//RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
		//else
		//RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
		free(p_response);
		break;
	}
#endif

#ifdef RIL_REQUEST_GET_HARDWARE_CONFIG
        case RIL_REQUEST_GET_HARDWARE_CONFIG:
            requestGetHardwareConfig(data, datalen, t);
            break;
#endif

#ifdef RIL_REQUEST_GET_HARDWARE_CONFIG
        case RIL_REQUEST_SHUTDOWN:
            requestShutdown(t);
            break;
 #endif

#ifdef RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE
        case RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE:
            requestSetCellInfoListRate(data, datalen, t);
            break;
 #endif

        case RIL_REQUEST_SET_TTY_MODE:
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
            
        case RIL_REQUEST_QUERY_TTY_MODE:    {
            int response[] = {0}; // * ((int *)response)[0] is == 0 for TTY off
            RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response)); 
            break;
        }

#ifdef RIL_REQUEST_IMS_REGISTRATION_STATE
        case RIL_REQUEST_IMS_REGISTRATION_STATE: {
            int response[] = {0, 0}; //  0 - Not registered
            RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response)); 
            break;
        }
 #endif

#ifdef RIL_REQUEST_SIM_OPEN_CHANNEL
        case RIL_REQUEST_SIM_OPEN_CHANNEL:
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0); 
            break;
#endif

#ifdef RIL_REQUEST_SIM_CLOSE_CHANNEL
        case RIL_REQUEST_SIM_CLOSE_CHANNEL:
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0); 
            break;        
#endif

#ifdef RIL_REQUEST_SET_INITIAL_ATTACH_APN
        case RIL_REQUEST_SET_INITIAL_ATTACH_APN:
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0); 
            break;
#endif

#ifdef RIL_REQUEST_GET_CELL_INFO_LIST
        case RIL_REQUEST_GET_CELL_INFO_LIST:
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0); 
            break;
#endif
   
        case RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE:
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;

        default:
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            break;
    }
}

/**
 * Synchronous call from the RIL to us to return current radio state.
 * RADIO_STATE_UNAVAILABLE should be the initial state.
 */
static RIL_RadioState
currentState()
{
    return sState;
}
/**
 * Call from RIL to us to find out whether a specific request code
 * is supported by this implementation.
 *
 * Return 1 for "supported" and 0 for "unsupported"
 */

static int
onSupports (int requestCode)
{
    (void ) requestCode;
    LOGI("Call OnSupports\r\n");
    return 1;
}

static void onCancel (RIL_Token t)
{
    (void) t;
    LOGI("Call OnCancel\r\n");
}

static const char * getVersion(void)
{
#if 1 //quectel
    onRequestCount = 0; //onNewCommandConnect will call this function, and RIL.java will send RIL_REQUEST_RADIO_POWER
#endif
    return REFERENCE_RIL_VERSION;
}

static void
setRadioState(RIL_RadioState newState)
{
    RIL_RadioState oldState;

    pthread_mutex_lock(&s_state_mutex);

    oldState = sState;

    LOGI("[%s]:oldState=%d, newState=%d\r\n", __func__, oldState, newState);

    if (s_closed > 0) {
        // If we're closed, the only reasonable state is
        // RADIO_STATE_UNAVAILABLE
        // This is here because things on the main thread
        // may attempt to change the radio state after the closed
        // event happened in another thread
        newState = RADIO_STATE_UNAVAILABLE;
    }

    if (sState != newState || s_closed > 0) {
        sState = newState;

        pthread_cond_broadcast (&s_state_cond);
    }

    pthread_mutex_unlock(&s_state_mutex);

    /* do these outside of the mutex */
    if (sState != oldState) {
        RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED,
                                    NULL, 0);

        /* FIXME onSimReady() and onRadioPowerOn() cannot be called
         * from the AT reader thread
         * Currently, this doesn't happen, but if that changes then these
         * will need to be dispatched on the request thread
         */
        if (sState == RADIO_STATE_SIM_READY) {
            onSIMReady();
        } else if (sState == RADIO_STATE_SIM_NOT_READY) {
            onRadioPowerOn();
        }
    }
}

/** Returns SIM_NOT_READY on error */
static SIM_Status
getSIMStatus()
{
    ATResponse *p_response = NULL;
    int err;
    int ret;
    char *cpinLine;
    char *cpinResult;

    if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
        ret = SIM_NOT_READY;
        goto done;
    }

    err = at_send_command_singleline("AT+CPIN?", "+CPIN:", &p_response);

    if (err != 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    switch (at_get_cme_error(p_response)) {
        case CME_SUCCESS:
            break;

        case CME_SIM_NOT_INSERTED:
            ret = SIM_ABSENT;
            goto done;

        default:
            ret = SIM_NOT_READY;
            goto done;
    }

    /* CPIN? has succeeded, now look at the result */

    cpinLine = p_response->p_intermediates->line;
    err = at_tok_start (&cpinLine);

    if (err < 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    err = at_tok_nextstr(&cpinLine, &cpinResult);

    if (err < 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    if (0 == strcmp (cpinResult, "SIM PIN")) {
        ret = SIM_PIN;
        goto done;
    } else if (0 == strcmp (cpinResult, "SIM PUK")) {
        ret = SIM_PUK;
        goto done;
    } else if (0 == strcmp (cpinResult, "PH-NET PIN")) {
        return SIM_NETWORK_PERSONALIZATION;
    } else if (0 != strcmp (cpinResult, "READY"))  {
        /* we're treating unsupported lock types as "sim absent" */
        ret = SIM_ABSENT;
        goto done;
    }

    at_response_free(p_response);
    p_response = NULL;
    cpinResult = NULL;

    ret = SIM_READY;

done:
    at_response_free(p_response);
    return ret;
}


/**
 * Get the current card status.
 *
 * This must be freed using freeCardStatus.
 * @return: On success returns RIL_E_SUCCESS
 */
static int getCardStatus(RIL_CardStatus_v6 **pp_card_status) {
    static RIL_AppStatus app_status_array[] = {
        // SIM_ABSENT = 0
        { RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_NOT_READY = 1
        { RIL_APPTYPE_SIM, RIL_APPSTATE_DETECTED, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_READY = 2
        { RIL_APPTYPE_SIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_PIN = 3
        { RIL_APPTYPE_SIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN },
        // SIM_PUK = 4
        { RIL_APPTYPE_SIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED, RIL_PINSTATE_UNKNOWN },
        // SIM_NETWORK_PERSONALIZATION = 5
        { RIL_APPTYPE_SIM, RIL_APPSTATE_SUBSCRIPTION_PERSO, RIL_PERSOSUBSTATE_SIM_NETWORK,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN }
    };
    RIL_CardState card_state;
    int num_apps;

    int sim_status = getSIMStatus();
    if (sim_status == SIM_ABSENT) {
        card_state = RIL_CARDSTATE_ABSENT;
        num_apps = 0;
    } else {
        card_state = RIL_CARDSTATE_PRESENT;
        num_apps = 1;
    }

    // Allocate and initialize base card status.
    RIL_CardStatus_v6 *p_card_status = malloc(sizeof(RIL_CardStatus_v6));
    p_card_status->card_state = card_state;
    p_card_status->universal_pin_state = RIL_PINSTATE_UNKNOWN;
    p_card_status->gsm_umts_subscription_app_index = RIL_CARD_MAX_APPS;
    p_card_status->cdma_subscription_app_index = RIL_CARD_MAX_APPS;
    p_card_status->ims_subscription_app_index = RIL_CARD_MAX_APPS;
    p_card_status->num_applications = num_apps;

    // Initialize application status
    int i;
    for (i = 0; i < RIL_CARD_MAX_APPS; i++) {
        p_card_status->applications[i] = app_status_array[SIM_ABSENT];
    }

    // Pickup the appropriate application status
    // that reflects sim_status for gsm.
    if (num_apps != 0) {
        // Only support one app, gsm
        p_card_status->num_applications = 1;
        p_card_status->gsm_umts_subscription_app_index = 0;

        // Get the correct app status
        p_card_status->applications[0] = app_status_array[sim_status];
    }

    *pp_card_status = p_card_status;
    return RIL_E_SUCCESS;
}

/**
 * Free the card status returned by getCardStatus
 */
static void freeCardStatus(RIL_CardStatus_v6 *p_card_status) {
    free(p_card_status);
}

static void onSIMStateChange (void *param)
{
    ATResponse *p_response;

    switch(getSIMStatus()) {
        case SIM_ABSENT:
        case SIM_PIN:
        case SIM_PUK:
        case SIM_NETWORK_PERSONALIZATION:
        default:
            setRadioState(RADIO_STATE_SIM_LOCKED_OR_ABSENT);
        return;

        case SIM_NOT_READY:
            setRadioState(RADIO_STATE_SIM_NOT_READY);        
        return;

        case SIM_READY:
            setRadioState(RADIO_STATE_SIM_READY);
        return;
    }
}

static void onSMSReady (void *param) {
    ATResponse *p_response = NULL;
    int err;
    int sms_ready = 1;

//AT+QINISTAT is used to query status of SIM/USIM card initialization.
    err = at_send_command_singleline("AT+QINISTAT", "+QINISTAT:", &p_response);
    if (err < 0 || p_response == NULL || p_response->success == 0) {
        
    } else {
        int status;
        char *line = p_response->p_intermediates->line;
        if (at_tok_start(&line) == 0) {
            if (at_tok_nextint(&line, &status) == 0) {
                if (ql_is_GSM) {
                    // 0 No initiallization
                    // 1 Ready to execute AT command
                    // 2 Phonebook has finished initialization
                    // 3 SMS has finished initialization
                     sms_ready = ((status & 3) == 3);                   
                } else if (ql_is_UC20) {
                    // 0 Initial state
                    // 1 CPIN READY. Operation like lock/unlock PIN is allowed
                    // 2 SMS initialization complete
                    // 4 Phonebook initialization complete
                    sms_ready = ((status & 2) == 2);
                } else {
                    sms_ready = (status != 0); // i donot konw by now!
                }
            }
        }
    }

    if (sms_ready) {
        if (ql_is_GSM) {
            /**
            *  Wythe: Modify on 2013-04-02 for 4.0 ril
            *  we support AT+CSMS=128 for GSM module and 
            *  AT+CSMS=1 for WCDMA module
            */
            at_send_command_singleline("AT+CSMS=128", "+CSMS:", NULL);

            /*
            * Always send SMS messages directly to the TE
            *
            * mode = 1 // discard when link is reserved (link should never be
            *             reserved)
            * mt = 2   // most messages routed to TE
            * bm = 2   // new cell BM's routed to TE
            * ds = 1   // Status reports routed to TE
            * bfr = 1  // flush buffer
            */
            at_send_command("AT+CNMI=1,2,2,1,1", NULL);
        } else {    
            at_send_command_singleline("AT+CSMS=1", "+CSMS:", NULL);
            /*
            * Always send SMS messages directly to the TE
            *
            * mode = 1 // discard when link is reserved (link should never be
            *             reserved)
            * mt = 2   // most messages routed to TE
            * bm = 2   // new cell BM's routed to TE
            * ds = 1   // Status reports routed to TE
            * bfr = 1  // flush buffer
            */
            at_send_command("AT+CNMI=1,2,0,1,0", NULL);
        }
        
        /*  SMS PDU mode */
        at_send_command("AT+CMGF=0", NULL);
    }else {
        RIL_requestTimedCallback (onSMSReady, NULL, &TIMEVAL_SIMPOLL);
    }
}

/**
 * SIM ready means any commands that access the SIM will work, including:
 *  AT+CPIN, AT+CSMS, AT+CNMI, AT+CRSM
 *  (all SMS-related commands)
 */

static void pollSIMState (void *param)
{
    ATResponse *p_response;
    int ret;

    if (sState != RADIO_STATE_SIM_NOT_READY) {
        // no longer valid to poll
        return;
    }

    switch(getSIMStatus()) {
        case SIM_ABSENT:
        case SIM_PIN:
        case SIM_PUK:
        case SIM_NETWORK_PERSONALIZATION:
        default:
            setRadioState(RADIO_STATE_SIM_LOCKED_OR_ABSENT);
        return;

        case SIM_NOT_READY:
            RIL_requestTimedCallback (pollSIMState, NULL, &TIMEVAL_SIMPOLL);
        return;

        case SIM_READY:
            setRadioState(RADIO_STATE_SIM_READY);
        return;
    }
}

/** returns 1 if on, 0 if off, and -1 on error */
static int isRadioOn()
{
    ATResponse *p_response = NULL;
    int err;
    char *line;
    char ret;

    err = at_send_command_singleline("AT+CFUN?", "+CFUN:", &p_response);

    if (err < 0 || p_response->success == 0) {
        // assume radio is off
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextbool(&line, &ret);
    if (err < 0) goto error;

    at_response_free(p_response);

    return (int)ret;

error:
    LOGE("[%s]:isRadioOn return error\n", __func__);
    at_response_free(p_response);
    return -1;
}

/**
 * Initialize everything that can be configured while we're still in
 * AT+CFUN=0
 */
static void initializeCallback(void *param)
{
    ATResponse *p_response = NULL;
    int err;

#if 1 //quectel
    if (currentState() == RADIO_STATE_SIM_READY) { //maybe only usb disconnect
    } else 
#endif
    setRadioState (RADIO_STATE_OFF);

    at_handshake();

#if 1 //quectel display module software version 
__get_ql_product:
    ql_is_UC20 = ql_is_EC20 = ql_is_UG95 = ql_is_GSM = 0;
    ql_product_version = NULL; //"GSMXX"	
    err = at_send_command_multiline("ATI", "\0", &p_response);
    if (!err && p_response && p_response->success) {
        ATLine *p_cur = p_response->p_intermediates;
        while (p_cur) {
             if (strStartsWith(p_cur->line, "Revision: ")) {
                ql_product_version = strdup(p_cur->line + strlen("Revision: "));
                break;
            }
            p_cur = p_cur->p_next;
        }
    }
    at_response_free(p_response);
    p_response = NULL;
    if (!ql_product_version) {
        sleep(1);
        goto __get_ql_product;
    }    
    LOGD("Quectel Product Revision: %s", ql_product_version);
    if (ql_is_XX("UC15") || ql_is_XX("UC20")) {
        ql_is_UC20 = 1;
        LOGD("UCXX");
    } else if (ql_is_XX("EC20")) {
        ql_is_EC20 = 1;
        LOGD("ECXX");
#if 0 //auto, LTE preferred
    at_send_command("AT+QCFG=\"nwscanmode\",0", NULL);
    at_send_command("AT+QCFG=\"nwscanseq\",04030201", NULL);
#endif
    } else if (ql_is_XX("UG95") || ql_is_XX("UG96")) {
        ql_is_UG95 = 1;
        LOGD("UGXX");
    } else {
        ql_is_GSM = 1;
        LOGD("GSMXX");
    }
    at_send_command_multiline("AT+CSUB", "\0", &p_response);
#endif

    /* note: we don't check errors here. Everything important will
       be handled in onATTimeout and onATReaderClosed */

    /*  atchannel is tolerant of echo but it must */
    /*  have verbose result codes */
    at_send_command("ATE0Q0V1", NULL);

    /*  No auto-answer */
    at_send_command("ATS0=0", NULL);
    
//Joe
    if (ql_mux_enabled) {
        at_send_command("AT+QURCCFG=\"URCPORT\",\"UART1\"", NULL);
        at_send_command("AT+QCFG=\"CMUX/URCPORT\",1", NULL);
    } else
        at_send_command("AT+QURCCFG=\"URCPORT\",\"usbat\"", NULL); //urcport",("usbat","usbmodem","uart1"

#if 1 // quectel Set DTR Function Mode 
//ON->OFF on DTR: Disconnect data call, change to command mode. During state DTR = OFF, auto-answer function is disabled
    at_send_command("AT&D2", NULL);
#endif

    /*  Extended errors */
    at_send_command("AT+CMEE=1", NULL);

    /*  Network registration events */
    at_send_command("AT+CREG=2", NULL);
    
//there is a change in the ME network registration status or a change of the network cell: 
//+CGREG: <stat>[, <lac>,<ci> ] 
    at_send_command("AT+CGREG=2", NULL); 

#if 1 //quectel
    if (ql_is_UC20) {
        at_send_command("AT+QINDCFG=\"all\",1", NULL);
        at_send_command("AT+QINDCFG=\"smsfull\",1", NULL);
    }
    //Quectel NITZ
    //Joe.Wang
    //2013-11-14
    at_send_command("AT+CTZU=1", NULL);
    at_send_command("AT+CTZR=2", NULL);

    if (ql_is_UC20 || ql_is_EC20)
        at_send_command("AT+QCFG=\"QMISYNC\",0", NULL);
    at_send_command("AT+QSCLK=1", NULL); //Configure Whether or not to Enter into Sleep Mode

#if 0
    at_send_command("AT+QCFG=\"usb/fullspeed\",1", NULL);
#endif
#endif

    /* assume radio is off on error */
    if (isRadioOn() != 1) {
        at_send_command("AT+CFUN=1", NULL);
        sleep(3);
    }
    err = at_send_command_singleline("AT+CPIN?", "+CPIN:", &p_response); ////may be busy, wait a moment
    if ((err != 0) || !p_response || at_get_cme_error(p_response))
        sleep(1);
    at_response_free(p_response);
    p_response = NULL;
   
    if (isRadioOn() > 0) {
#if 1 //quectel
        if ((currentState() == RADIO_STATE_SIM_READY) && (getSIMStatus() == SIM_READY)) {//maybe only usb disconnect
            RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED, NULL, 0);
            RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
            onSIMReady();
        } else {
            setRadioState (RADIO_STATE_SIM_NOT_READY); 
        }
#else
        setRadioState (RADIO_STATE_SIM_NOT_READY);
#endif
    }
}

static void waitForClose()
{
    pthread_mutex_lock(&s_state_mutex);

    while (s_closed == 0) {
        pthread_cond_wait(&s_state_cond, &s_state_mutex);
    }
    
    pthread_mutex_unlock(&s_state_mutex);
}

/**
 * Called by atchannel when an unsolicited line appears
 * This is called on atchannel's reader thread. AT commands may
 * not be issued here
 */
static void onUnsolicited (const char *s, const char *sms_pdu)
{
    char *line = NULL;
    int err;

    /* Ignore unsolicited responses until we're initialized.
     * This is OK because the RIL library will poll for initial state
     */
    if (sState == RADIO_STATE_UNAVAILABLE) {
        return;
    }

    if (strStartsWith(s, "%CTZV:")) {
        /* TI specific -- NITZ time */
        char *response;

        line = strdup(s);
        at_tok_start(&line);

        err = at_tok_nextstr(&line, &response);

        if (err != 0) {
            LOGE("invalid NITZ line %s\n", s);
        } else {
            RIL_onUnsolicitedResponse (
                RIL_UNSOL_NITZ_TIME_RECEIVED,
                response, strlen(response));
        }
    } else if (strStartsWith(s,"+CRING:")
                || strStartsWith(s,"RING")
                || strStartsWith(s,"NO CARRIER")
                || strStartsWith(s,"+CCWA")
    ) {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
            NULL, 0);
    } else if (strStartsWith(s,"+CREG:")
                || strStartsWith(s,"+CGREG:")
    ) {
#if 1 //quectel
    if (currentDataServiceState() && (network_debounce_time == 0))
        network_debounce_time = NETWORK_DEBOUNCE_TIMEOUT;
#endif
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,
            NULL, 0);
    } else if (strStartsWith(s, "+CMT:")) {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS,
            sms_pdu, strlen(sms_pdu));
    } else if (strStartsWith(s, "+CDS:")) {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT,
            sms_pdu, strlen(sms_pdu));
    } else if (strStartsWith(s, "+CGEV:")) {
        /* Really, we can ignore NW CLASS and ME CLASS events here,
         * but right now we don't since extranous
         * RIL_UNSOL_DATA_CALL_LIST_CHANGED calls are tolerated
         */
        /* can't issue AT commands here -- call on main thread */
        RIL_requestTimedCallback (onDataCallListChanged, NULL, NULL);
    } 
#if 1 //quectel
    else if(strStartsWith(s,"+CTZE:")) { //NITZ
        //+CTZE: "+32",0,"2014/05/05,05:05:30"
        //yy/mm/dd,hh:mm:ss(+/-)tz,dt
        char *tz = NULL;
        int dt;
        char *n_time = NULL;
        char *response = NULL;

        line = strdup(s);
        at_tok_start(&line);
        err = at_tok_nextstr(&line,&tz);
        if (err < 0) return;
        err = at_tok_nextint(&line,&dt);
        if (err < 0) return;
        err = at_tok_nextstr(&line,&n_time);
        if (err < 0) return;

        if (n_time[4] == '/')
            asprintf(&response,"%s%s,%d",n_time+2,tz,dt); //2014 -> 14
        else    
            asprintf(&response,"%s%s,%d",n_time,tz,dt);
        time_zone_report = 1;

        RIL_onUnsolicitedResponse (RIL_UNSOL_NITZ_TIME_RECEIVED,response, strlen(response));
    } else if (strStartsWith(s, "+CMTI:")) {
        char *memory = NULL;
        int index;
        line = strdup(s);
        at_tok_start(&line);
        err = at_tok_nextstr(&line,&memory);
        if (err < 0) return;
        if(!strcmp("SM",memory))
        {
            err = at_tok_nextint(&line,&index);
            if (err < 0) return;
             RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_NEW_SMS_ON_SIM,&index, sizeof(int *));
        }
    } else if (strStartsWith(s, "+QIND: \"smsfull\"")) {
        char *memory = NULL;
        char *tmp = NULL;
        line = strdup(s);
        at_tok_start(&line);
        err = at_tok_nextstr(&line,&tmp);
        if (err < 0) return;
        err = at_tok_nextstr(&line,&memory);
        if (err < 0) return;
        if(!strcmp("SM",memory))
        {
             RIL_onUnsolicitedResponse (RIL_UNSOL_SIM_SMS_STORAGE_FULL,NULL,0);
        }
#if 1 // RIL will get sim state by pollSIMState() 
    } else if (strStartsWith(s, "+CPIN: READY") || strStartsWith(s, "+QUSIM:") || strStartsWith(s, "+QIND: SMS DONE") || strStartsWith(s, "+QIND: PB DONE")) {
        if (currentState() == RADIO_STATE_SIM_LOCKED_OR_ABSENT) 
            RIL_requestTimedCallback (onSIMStateChange, NULL, NULL); //setRadioState(RADIO_STATE_SIM_READY); //cannot call at_send_command() here, because they are in same thread
#endif
    } else if (strStartsWith(s, "+CPIN: NOT READY")) {
        if (currentState() == RADIO_STATE_SIM_READY)
            RIL_requestTimedCallback (onSIMStateChange, NULL, NULL); //setRadioState(RADIO_STATE_SIM_READY); //cannot call at_send_command() here, because they are in same thread
    } else if (strStartsWith(s, "+CUSD")) {
        char *response[2];
        char *data;
        char *mode;
        int dcs;
        int outlen = 0;
        int err;

        ussd_pending_index++;
        line = strdup(s);
        at_tok_start(&line);
        err = at_tok_nextstr(&line,&mode);
        if(err != 0)
        {
            LOGE("at_tok_nextstr[mode] error");
            return ;
        }
        err = at_tok_nextstr(&line,&data);
        if(err != 0)
        {
            LOGE("at_tok_nextstr[data] error");
            onUssdResponse(mode);
            return ;
        }
        err = at_tok_nextint(&line,&dcs);
        if(err != 0)
        {
            LOGE("at_tok_nextstr[dcs] error");
            return ;
        }
        dcs &= 0x0c;

        response[0] = (char *)malloc(strlen(mode) + 1);
        memcpy(response[0],mode,strlen(mode) + 1);

        response[1] = (char *)malloc(strlen(data) + 1);

#ifdef CUSD_USE_UCS2_MODE
        if(1)//UCS2
#else
        if(dcs == 0x08)//UCS2
#endif
        {
            //unsigned char *tmp = (unsigned char *)malloc(sizeof(data)/2*3);
            size_t i = 0;
            unsigned char tmp[512];
            while(i < strlen(data))
            {   
                tmp[i/2] = (unsigned char)gsm_hex2_to_byte(&data[i]);
                i += 2;
            }   
            outlen = ucs2_to_utf8(tmp,i/4,(bytes_t)response[1]);
            response[1][outlen] = 0;
            //free(tmp);
        }
#if 0 // CUSD_USE_UCS2_MODE
        else if(dcs == 0x04)// 8 bit data
        {
            //memcpy(response[1],data,strlen(data) + 1);
            outlen = gsm_hex_to_bytes((bytes_t)data,strlen(data),(bytes_t)response[1]);
        }
        else//GSM 7 bit data, infact module gives us GSM 8 bit data
        {
            // memcpy(response[1],data,strlen(data) + 1);
            outlen = utf8_from_gsm8((cbytes_t)data,strlen(data),(bytes_t)response[1]);
        }
#endif
        LOGI("len:%d response[0]:%s",strlen(response[0]),response[0]);
        LOGI("len:%d[%d] response[1]:%s",strlen(response[1]),outlen,response[1]);

        RIL_onUnsolicitedResponse(RIL_UNSOL_ON_USSD, response, sizeof(response[0]) + sizeof(response[1]));

        free(response[0]);
        free(response[1]);
    } 
#endif
}

/* Called on command or reader thread */
static void onATReaderClosed()
{
    LOGI("AT channel closed\n");
    at_close();
    s_closed = 1;

#if 1 //quectel
    setDataServiceState(0);
    if (!strncmp(PPP_TTY_PATH, "ppp", 3))
        ql_kill_pppd(SIGKILL);
    else
        ql_kill_ndis(SIGKILL);
#ifdef QUECTEL_DEBUG //quectel //for debug-purpose, record logcat msg to file
    log_dmesg("onATReaderClosed");
#endif
    if (currentState() == RADIO_STATE_SIM_READY) {//maybe only usb disconnect
        pthread_mutex_lock(&s_state_mutex);
        pthread_cond_broadcast (&s_state_cond);
        pthread_mutex_unlock(&s_state_mutex);
        return;   
    } 
#endif
    setRadioState (RADIO_STATE_UNAVAILABLE);
}

/* Called on command thread */
static void onATTimeout()
{
    LOGI("AT channel timeout; closing\n");
    at_close();

    s_closed = 1;

    /* FIXME cause a radio reset here */

    setRadioState (RADIO_STATE_UNAVAILABLE);
#ifdef QUECTEL_DEBUG //quectel //for debug-purpose, record logcat msg to file
    //log_dmesg("onATTimeout");
#endif
}

static void usage(char *s)
{
#ifdef RIL_SHLIB
    fprintf(stderr, "reference-ril requires: -p <tcp port> or -d /dev/tty_device\n");
#else
    fprintf(stderr, "usage: %s [-p <tcp port>] [-d /dev/tty_device]\n", s);
    exit(-1);
#endif
}

static void clean_up_child_process(int signal_num) {
    /* clean up child process */
    while(waitpid(-1, NULL, WNOHANG) > 0); 
}

static void *
mainLoop(void *param)
{
    int fd;
    int ret;

#ifdef QUECTEL_DEBUG //quectel //for debug-purpose, record logcat msg to file
//you can fetch logfiles to host-pc by adb tools using command "adb pull /data/ql_log/"
    char logcat_cmd[100];
    time_t rawtime;
    struct tm *timeinfo;	
    time(&rawtime);
    timeinfo=localtime(&rawtime );
    system("/system/bin/mkdir /data/ql_log");
    sprintf(logcat_cmd, "/system/bin/logcat -v time -f /data/ql_log/%02d%02d_%02d%02d%02d_logcat.txt &",
		timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    system(logcat_cmd);
    sprintf(logcat_cmd, "/system/bin/logcat -b radio -v time -f /data/ql_log/%02d%02d_%02d%02d%02d_radio.txt &",
		timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    system(logcat_cmd);
#endif

    signal(SIGCHLD, clean_up_child_process); //becasue use fork() to start and stop pppd
    LOGD("Quectel RIL Version: " REFERENCE_RIL_VERSION);
    LOGI("mainLoop Start\r\n");
    AT_DUMP("== ", "entering mainLoop()", -1 );
    at_set_on_reader_closed(onATReaderClosed);
    at_set_on_timeout(onATTimeout);

    for (;;) {
            //1. can not get at port for long time, maybe quectel-module is power-off
            //2. when AT timeout occurs, need to reboot quectel-module
                // turn off quectel-module's power-supply here
                //sleep(2); //wait power-supply stable
                //turn on quectel-module's power-supply here
                //sleep(2); //wait power-supply stable
                //use pwr-key to turn on quectel-module here
                //sleep(5); //wait quectel-power boot up
    if (ql_mux_enabled) {
        if (gsm0710muxd(s_device_path, cmux_speed, cmux_ctsrts)) {
            sleep(3);
            continue;
            }
    } else { 
        if (s_device_path == ql_ttyAT) {
            char atdevice[10];
            if (!ql_get_ttyAT(atdevice)) {
                sleep(3);
                continue;
            }
            sprintf(ql_ttyAT, "/dev/%s", atdevice);
            LOGD("quectel at port is %s", ql_ttyAT);
        }
    }
#ifdef QUECTEL_DEBUG //quectel //for debug-purpose, record logcat msg to file
        log_dmesg("mainLoop");
#endif        

        fd = -1;
        while  (fd < 0) {
            if (s_device_path != NULL) {
                if (ql_mux_enabled) {
                    LOGD("open " CMUX_AT_PORT);
                    fd = open (CMUX_AT_PORT, O_RDWR);
                    LOGD("fd = %d", fd);
                } else {
                fd = open (s_device_path, O_RDWR);
                }
                if ( fd >= 0 ) {
                    /* disable echo on serial ports */
                    struct termios  ios;
                    memset(&ios, 0, sizeof(ios));
                    tcgetattr( fd, &ios );
                    cfmakeraw(&ios);
                    ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
                    cfsetispeed(&ios, B115200);
                    cfsetospeed(&ios, B115200);
                    tcsetattr( fd, TCSANOW, &ios );
                    LOGD("open device %s correctly\n", s_device_path);
                    tcflush(fd, TCIOFLUSH);
                }
            }

            if (fd < 0) {
                LOGE("open device %s error for %s\n", s_device_path, strerror(errno));
                perror ("opening AT interface. retrying...");
#if 1 //quectel
                sleep(3);
#else
                sleep(10);
#endif
                /* never returns */
            }
        }

        s_closed = 0;
        ret = at_open(fd, onUnsolicited);

        if (ret < 0) {
            LOGE ("AT error %d on at_open\n", ret);
            return 0;
        }

        RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_0);

        // Give initializeCallback a chance to dispatched, since
        // we don't presently have a cancellation mechanism
        sleep(1);

        waitForClose();
        LOGI("Re-opening after close");
    }
}

#ifdef RIL_SHLIB

pthread_t s_tid_mainloop;

const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *env, int argc, char **argv)
{
    int ret;
    int fd = -1;
    int opt;
    pthread_attr_t attr;

    char version_str[PROPERTY_VALUE_MAX] = {'\0'};
    int version = 0xffff;
    int ril_version = -1;
    if (property_get("ro.build.version.release", version_str, NULL) > 0) {
        version = (version_str[0] - '0') * 10 + (version_str[2] - '0');
    }
    LOGD("[ro.build.version.release]: [%s]", version_str); 
    if (version <= 40)
        ril_version = 6;
    else if (version == 41)
        ril_version = 6;
    else if (version == 42)
        ril_version = 7;
    else if (version == 43)
        ril_version = 8;
    else if (version == 44)
        ril_version = 9;
    else if (version == 50)
        ril_version = 10;
    else if (version == 51)
        ril_version = 11;
    else 
        LOGE("Unsupport Android Version by Quectel Now!!!!");
    LOGD("Android Version: %d, RIL_VERSION: %d / %d", version, ril_version, RIL_VERSION);
    //s_callbacks.version = RIL_VERSION;

    s_rilenv = env;

    while ( -1 != (opt = getopt(argc, argv, "p:d:s:c:C:B:b:"))) {
        switch (opt) {
            case 'p':
                s_port = atoi(optarg);
                if (s_port == 0) {
                    usage(argv[0]);
                    return NULL;
                }
                LOGI("Opening loopback port %d\n", s_port);
            break;

            case 'd':
                s_device_path = optarg;
                LOGI("Opening tty device %s\n", s_device_path);
            break;

            case 's':
                s_device_path   = optarg;
                s_device_socket = 1;
                LOGI("Opening socket %s\n", s_device_path);
            break;

            case 'c':
                LOGI("clientID = %d\n", atoi(optarg));
            break;

            case 'C':
                cmux_ctsrts = !!atoi(optarg);
                LOGI("cmux_ctsrts = %d\n", cmux_ctsrts);
              break;

            case 'b':
            case 'B':
                cmux_speed = atoi(optarg);
                LOGI("cmux_speed = %d\n", cmux_speed);
            break;
              
            default:
                usage(argv[0]);
                return NULL;
        }
    }

    if (s_port < 0 && s_device_path == NULL) {
#if 1 //quectel //get ttyAT dymanic
    s_device_path = ql_ttyAT;
#else
        usage(argv[0]);
        return NULL;
#endif
    }

    if (s_device_path != ql_ttyAT) {
        ql_mux_enabled = 1;
        if (strStartsWith(s_device_path, "/dev/ttyUSB")) {
            if (atoi(&s_device_path[strlen("/dev/ttyUSB")]) > 1)
                ql_mux_enabled = 0;
        }
    }

    pthread_attr_init (&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&s_tid_mainloop, &attr, mainLoop, NULL);

    return &s_callbacks;
}
#else /* RIL_SHLIB */
int main (int argc, char **argv)
{
    int ret;
    int fd = -1;
    int opt;

    while ( -1 != (opt = getopt(argc, argv, "p:d:"))) {
        switch (opt) {
            case 'p':
                s_port = atoi(optarg);
                if (s_port == 0) {
                    usage(argv[0]);
                }
                LOGI("Opening loopback port %d\n", s_port);
            break;

            case 'd':
                s_device_path = optarg;
                LOGI("Opening tty device %s\n", s_device_path);
            break;

            case 's':
                s_device_path   = optarg;
                s_device_socket = 1;
                LOGI("Opening socket %s\n", s_device_path);
            break;

            default:
                usage(argv[0]);
        }
    }

    if (s_port < 0 && s_device_path == NULL) {
        usage(argv[0]);
    }

    RIL_register(&s_callbacks);

    mainLoop(NULL);

    return 0;
}

#endif /* RIL_SHLIB */

