/*
 * program name: uds-server-simulator
 * version: 1.1.2
 * date: 2023-10-12
 * author: Honinbon
 * 
 * GNU General Public License v2.0
 * 
 */  

#include <getopt.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

#include "uds-server-simulator.h"
#include "third/cJSON.h"

/* Globals */
char *version = "v1.1.2";

int io_control_id_flag = 0;             // 0-false 1-true
long io_control_seconds = 0;
long io_control_microseconds = 0;

int diag_func_req_id = 0;               // default 0
int diag_phy_req_id = 0;                // default 0
int diag_phy_resp_id = 0;               // default 0

long change_to_non_default_session_seconds = 0;          // seconds part
long change_to_non_default_session_microseconds = 0;     // microseconds part
const long S3Server_timer = 5;                           // default 5s

int current_session_mode = 1;           // default session mode(1), only support 1 and 3 in this version.
int current_security_level = 0;         // default not unlocked(0), only support 3, 19 and 21 in this version.
int current_security_phase_3 = 0;       // default 0, there are two phases: 1 and 2.
int current_security_phase_19 = 0;      // default 0, there are two phases: 1 and 2.
int current_security_phase_21 = 0;      // default 0, there are two phases: 1 and 2.
uint8_t *current_seed_3 = NULL;         // store the current 27's seed of security level 0x03.
uint8_t *current_seed_19 = NULL;        // store the current 27's seed of security level 0x19.
uint8_t *current_seed_21 = NULL;        // store the current 27's seed of security level 0x21.
int security_access_error_attempt = 0;  // store service 27 error attempt number, only limit sl 19 and 21.
unsigned long security_access_lock_time = 0;      // store the lock time of security access, only limit sl 19 and 21.

uint8_t tmp_store[8] = {0};

int flow_control_flag = 0;              // 0-false 1-true
uint8_t st_min = 0;                     // us

/* This space is for $34 and $35 */
uint8_t *firmwareSpace = NULL;
int SPACE_SIZE = 64 * 1024;        // 64K
int req_transfer_data_len = 0;
int req_transfer_data_add = 0;
int req_transfer_type = 0;           // 0x34 or 0x35
int req_transfer_block_num = 0;
int req_transfer_block_counter = 0;

/* This is for $22 flow control packets */
uint8_t gBuffer[256] = {0};
int gBufSize = 0;
int gBufLengthRemaining = 0;
int gBufCounter = 0;

/* This is for $2E and $36 flow control packets */
uint8_t ggBuffer[256] = {0};
int ggBufSize = 0;
int ggBufLengthRemaining = 0;
int ggBufCounter = 0;
int ggSID = 0;


/********************************** DID Supported Start **********************************/
/* DID for 22 & 2E services, write DID value without authentication */
int DID_No_Security[100] = {0};
int DID_No_Security_Num = 0;

/* DID for 22 & 2E services, write DID value with 27 03 */
int DID_Security_03[100] = {0};
int DID_Security_03_Num = 0;

/* DID for 22 & 2E services, write DID value with 27 19 */
int DID_Security_19[100] = {0};
int DID_Security_19_Num = 0;

/* DID for 22 & 2E services, write DID value with 27 21 */
int DID_Security_21[100] = {0};
int DID_Security_21_Num = 0;

/* DID number for 22 & 2E services */
int DID_NUM = 0;

/* DID key-value for 22 & 2E services */
struct DIDKeyValuePair {
    int key;
    uint8_t value[256];   
} pairs[256];

/* DID for 2F service */
int DID_IO_Control[100] = {0};
int DID_IO_Control_Num = 0;
/********************************** DID Supported End **********************************/


/********************************** uds_server_init Start **********************************/
void isJsonObjNull(cJSON *object, char *str) {
    if (object == NULL) {
        printf("## THE %s IS NOT EXISTED ##\n", str);
        exit(1);
    }
}

void isValueJsonString(cJSON *object) {
    if (object->type != cJSON_String) {
        printf("## PLEASE CONFIG %s's VALUE TO STRING TYPE ##\n", object->string);
        exit(1);
    }
}

int set_diag_id(cJSON *items, char *key_name) {
    cJSON *diag_id_s = cJSON_GetObjectItem(items, key_name);
    isJsonObjNull(diag_id_s, key_name);
    isValueJsonString(diag_id_s);
    // printf("%#x\n", strtol(diag_id_s->valuestring, NULL, 16));
    if (diag_id_s->valuestring == "") {
        return 0;
    }
    return strtol(diag_id_s->valuestring, NULL, 16);
}

int DID_assignment(cJSON *items, char *key_name, int *DID_Arrary) {
    int i=0;
    static int k=0;
    cJSON *DID_struct = cJSON_GetObjectItem(items, key_name);
    if(DID_struct == NULL)
        return i;

    if (DID_struct->type == cJSON_Object) {
        cJSON *obj = DID_struct->child;
        while (obj) {
            isJsonObjNull(obj, NULL);
            isValueJsonString(obj);
            DID_Arrary[i] = strtol(obj->string, NULL, 16);
            i++;
            pairs[k].key = 0;
            memset(pairs[k].value, 0, sizeof(pairs[k].value));
            pairs[k].key = strtol(obj->string, NULL, 16);
            strncpy(pairs[k].value, obj->valuestring, strlen(obj->valuestring));
            k++;
            obj = obj->next;
            // printf("%x\n", DID_Arrary[i-1]);
            // printf(":%#x :%s :%d :%d\n", pairs[k-1].key, pairs[k-1].value, k-1, i-1);
            // printf("#################################################\n");
        }
        return i;
    }

    if (DID_struct->type == cJSON_Array) {
        cJSON *arr = DID_struct->child;
        while (arr) {
            isJsonObjNull(arr, NULL);
            isValueJsonString(arr);
            DID_Arrary[i] = strtol(arr->valuestring, NULL, 16);
            i++;
            arr = arr->next;
            // printf("%x\n", DID_Arrary[i-1]);
        }
        return i;
    }

    printf("## the format of %s's value is not right. ##\n", DID_struct->string);
    exit(1);
}

// char lower2upper(char ch){
//     if((ch >= 97) && (ch <= 122))   // lower character
//         return ch ^ 32;
//     else
//         return ch;
// }

void uds_server_init(cJSON *root, char *ecu) {
    char *current_ecu = NULL;
    if(ecu != NULL){
        current_ecu = ecu; 
    }else{
        cJSON *CURRENT_ECU = cJSON_GetObjectItem(root, "CURRENT_ECU");
        isJsonObjNull(CURRENT_ECU, "CURRENT_ECU");
        isValueJsonString(CURRENT_ECU);
        current_ecu = CURRENT_ECU->valuestring;
    }

    // 64K
    firmwareSpace = malloc(SPACE_SIZE);
    char* test_str = "Hello world";
    strncpy(firmwareSpace, test_str, strlen(test_str));

    // for(int i=0; i<strlen(current_ecu); i++){
    //     *(current_ecu+i) = lower2upper(*(current_ecu+i));
    // }

    cJSON *items = cJSON_GetObjectItem(root, current_ecu);
    isJsonObjNull(items, current_ecu);

    diag_func_req_id = set_diag_id(items, "func_req_id");
    diag_phy_req_id = set_diag_id(items, "phy_req_id");
    diag_phy_resp_id = set_diag_id(items, "phy_resp_id");
    if (diag_phy_req_id == 0 || diag_phy_resp_id == 0) {
        printf("## PLEASE SET CORRECT DIAG REQ & RESP ID ##\n");
        exit(1);
    }

    DID_No_Security_Num = DID_assignment(items, "DID_No_Security", DID_No_Security);
    DID_Security_03_Num = DID_assignment(items, "DID_Security_03", DID_Security_03);
    DID_Security_19_Num = DID_assignment(items, "DID_Security_19", DID_Security_19);
    DID_Security_21_Num = DID_assignment(items, "DID_Security_21", DID_Security_21);
    DID_NUM = (DID_No_Security_Num + DID_Security_03_Num + DID_Security_19_Num + DID_Security_21_Num);

    DID_IO_Control_Num = DID_assignment(items, "DID_IO_Control", DID_IO_Control);
}
/********************************** uds_server_init End **********************************/


void reset_relevant_variables() { // when session mode changed
    current_security_level = 0;       
    current_security_phase_3 = 0;       
    current_security_phase_19 = 0;   
    current_security_phase_21 = 0;  
    current_seed_3 = NULL;         
    current_seed_19 = NULL;      
    current_seed_21 = NULL;  
    security_access_error_attempt = 0; 
    flow_control_flag = 0;
    st_min = 0;
    gBufSize = 0;
    gBufLengthRemaining = 0;
    gBufCounter = 0;
    memset(gBuffer, 0, sizeof(gBuffer));
    ggBufSize = 0;
    ggBufLengthRemaining = 0;
    ggBufCounter = 0;
    ggSID = 0;
    memset(ggBuffer, 0, sizeof(ggBuffer));
    memset(tmp_store, 0, sizeof(tmp_store));
    req_transfer_data_len = 0;
    req_transfer_data_add = 0;
    req_transfer_type = 0;
    req_transfer_block_num = 0;
    req_transfer_block_counter = 0;
}

void udelay(int min) {
    struct timeval tv = {0};
    tv.tv_usec = min;
    select(0, NULL, NULL, NULL, &tv);
}

char int2nibble(int two_char, int position) {
    if (position != 0 && position != 1)
        return NULL;
    char str[2];
    sprintf(str, "%02x", two_char);
    return str[position];
}

unsigned int get_did_from_frame(struct can_frame frame) {
    char first_char = int2nibble(frame.data[0], 0);
    int did_high_byte, did_low_byte;
    if (first_char == '0') {
        did_high_byte = frame.data[2];
        did_low_byte = frame.data[3];
    }
    if (first_char == '1') {
        did_high_byte = frame.data[3];
        did_low_byte = frame.data[4];
    }
    unsigned char bytes[] = {did_high_byte, did_low_byte}; //	two bytes of DID
    unsigned int did = (bytes[0] << 8) | bytes[1];         //	DID hex int value
    return did;
}

uint8_t *seed_generate(int sl) {
    uint8_t *seed_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 4); // store 27's 4-byte seed
    if (sl == 0x03 || sl == current_security_level) {
        seed_ptr[0] = 0x00;
        seed_ptr[1] = 0x00;
        seed_ptr[2] = 0x00;
        seed_ptr[3] = 0x00;
        return seed_ptr;
    }

    if (sl == 0x19 || sl == 0x21) {
        uint8_t str[3];
        int ret;
        int num;
        srand((unsigned int)time(NULL));
        for (int i = 0; i < 4; i++) {
            ret = rand();
            sprintf(str, "%02d", ret % 100);
            num = strtol(str, NULL, 16);
            seed_ptr[i] = (uint8_t)num;
        }
        return seed_ptr;
    }
}

uint8_t *security_algorithm(uint8_t *seed_ptr, int sl) {
	uint8_t *key_ptr = (uint8_t *)malloc(sizeof(uint8_t)*4);	// store 27's 4-byte key 
    
	if (sl == 0x04) {
		key_ptr[0] = 0xde;
		key_ptr[1] = 0xad;
		key_ptr[2] = 0xbe;
		key_ptr[3] = 0xef;
        return key_ptr;
	}

    if (sl == 0x1A || sl == 0x22) {
        uint8_t Seed[4];
        uint8_t Const[4];
        uint8_t Key[4];
        uint32_t wConst = 0xdeadbeef;
        
        Seed[0] = *seed_ptr;
        Seed[1] = *(seed_ptr+1);
        Seed[2] = *(seed_ptr+2);
        Seed[3] = *(seed_ptr+3);

        Const[3] = (uint8_t)((wConst & 0xff000000) >> 24);
        Const[2] = (uint8_t)((wConst & 0x00ff0000) >> 16);
        Const[1] = (uint8_t)((wConst & 0x0000ff00) >> 8);
        Const[0] = (uint8_t)(wConst & 0x000000ff);

        Key[0] = Const[0] * (Seed[0] * Seed[0]) + Const[1] * (Seed[1] * Seed[1]) + Const[2] * (Seed[0] * Seed[1]);
        Key[1] = Const[0] * (Seed[0]) + Const[1] * (Seed[1]) + Const[3] * (Seed[0] * Seed[1]);
        Key[2] = Const[0] * (Seed[2] * Seed[3]) + Const[1] * (Seed[3] * Seed[3]) + Const[2] * (Seed[2] * Seed[3]);
        Key[3] = Const[0] * (Seed[2] * Seed[3]) + Const[1] * (Seed[3]) + Const[3] * (Seed[2] * Seed[3]);

        key_ptr = Key;
		return key_ptr;
    }
}

void send_negative_response(int can, int sid, int nrc) {
    struct can_frame resp;
    resp.can_id = diag_phy_resp_id;
    resp.can_dlc = 8;
    resp.data[0] = 0x03;
    resp.data[1] = 0x7F;
    resp.data[2] = sid;
    resp.data[3] = nrc;
    resp.data[4] = 0x00;
    resp.data[5] = 0x00;
    resp.data[6] = 0x00;
    resp.data[7] = 0x00;
    write(can, &resp, CAN_MTU);
    return;
}

void flow_control_push_to(int can) {    // referred to Craig Smith's uds-server.
    struct can_frame frame;
    frame.can_id = diag_phy_resp_id;
    while (gBufLengthRemaining > 0) {
        if (gBufLengthRemaining > 7) {
            frame.can_dlc = 8;
            frame.data[0] = gBufCounter;
            memcpy(&frame.data[1], gBuffer + (gBufSize - gBufLengthRemaining), 7);
            write(can, &frame, CAN_MTU);
            gBufCounter++;
            if (gBufCounter == 0x30)
                gBufCounter = 0x20;
            gBufLengthRemaining -= 7;
        } else {
            frame.can_dlc = 8;
            frame.data[0] = gBufCounter;
            memcpy(&frame.data[1], gBuffer + (gBufSize - gBufLengthRemaining), gBufLengthRemaining);
            gBufLengthRemaining+=1;
            for(; gBufLengthRemaining<=7; gBufLengthRemaining++) {
                frame.data[gBufLengthRemaining] = 0x00;
            }
            write(can, &frame, CAN_MTU);
            gBufLengthRemaining = 0;
        }
        udelay(st_min);
    }
    memset(gBuffer, 0, sizeof(gBuffer));   // clear did data buffer
}

void isotp_send_to(int can, uint8_t *data, int size) {  // referred to Craig Smith's uds-server.
    // send did's data: server to client
    struct can_frame frame;
    int left = size;
    int counter;
    int nbytes;

    // if (size > 4095) { // 0xFFF=4095
    //     send_negative_response(can, UDS_SID_READ_DATA_BY_ID, INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT);
    //     return;
    // }

    frame.can_id = diag_phy_resp_id;

    if (size < 8) { // send single frame
        frame.can_dlc = 8;
        frame.data[0] = size;
        memcpy(&frame.data[1], data, size);
        size+=1;
        for(; size<=7; size++) {
            frame.data[size] = 0x00;
        }
        nbytes = write(can, &frame, CAN_MTU);
        if (nbytes < 0)
            perror("send single frame error.");
    } else {    // send multi frame
        frame.can_dlc = 8;
        if(size>=0 && size<=0xFF) {
            frame.data[0] = 0x10;
            frame.data[1] = size;
        }
        if(size>=0x100 && size<=0xFFF) {
            frame.data[0] = 0x10 + ((size & 0x00000F00) >> 8);
            frame.data[1] = (size & 0x000000FF);
        }
        memcpy(&frame.data[2], data, 6);
        nbytes = write(can, &frame, CAN_MTU);
        if (nbytes < 0)
            perror("send first frame error.");
        left -= 6;
        counter = 0x21;

        memcpy(gBuffer, data, size); // Size is restricted to < 4096
        gBufSize = size;
        gBufLengthRemaining = left;
        gBufCounter = counter;

        flow_control_flag = 1;
    }
}


/********************************** NRC Handle Start **********************************/
/* NRC 0x12 SubFunctionNotSupported */
int isSubFunctionSupported(int sid, int sf) {
    switch (sid) {
        case UDS_SID_DIAGNOSTIC_CONTROL:
            if (sf == 0x01 || sf == 0x02 || sf == 0x03) 
                return 0;
            break;
        case UDS_SID_TESTER_PRESENT:
            if (sf == 0x00 || sf == 0x80)
                return 0;
            break;
        case UDS_SID_SECURITY_ACCESS:
            if (sf == 0x03 || sf == 0x04 || sf == 0x19 || sf == 0x1A || sf == 0x21 || sf == 0x22)
                return 0;
            break;
        case UDS_SID_READ_DATA_BY_ID:   // 0x22 No SF
        case UDS_SID_WRITE_DATA_BY_ID:  // 0x2E No SF
        case UDS_SID_IO_CONTROL_BY_ID:  // 0x2F No SF
            return 0;
        default:
            printf("please add the new SID in the switch-case statement.\n");
            break;
    }
    return SUB_FUNCTION_NOT_SUPPORTED;
}

/* NRC 0x13 incorrectMessageLengthOrInvalidFormat */
int isIncorrectMessageLengthOrInvalidFormat(struct can_frame frame) {
    int first_byte = frame.data[0];
    char first_char = int2nibble(first_byte, 0);
    char second_char = int2nibble(first_byte, 1);
    int len = sizeof(frame.data) / sizeof(frame.data[0]);
    int sid;

    // printf("%d\n", frame.can_dlc);
    // printf("%d %d %d\n", len, sizeof(frame.data), sizeof(frame.data[0]));

    if (frame.can_dlc != 8 )  // must padding to 8 bytes
        return -1;
    if (first_char == '0') {	// single frame 0x00-0x07
        sid = frame.data[1];
        switch (sid) {
            case UDS_SID_DIAGNOSTIC_CONTROL:
            case UDS_SID_TESTER_PRESENT:
                if (first_byte == 0x02)
                    return 0;
                break;
            case UDS_SID_SECURITY_ACCESS: // not support the field "securityAccessDataRecord" in this verison
                if (first_byte == 0x02 || first_byte == 0x06)
                    return 0;
                break;
            case UDS_SID_READ_DATA_BY_ID: // only support to read a DID per request frame in this version
                if (first_byte == 0x03)
                    return 0;
                break;
            case UDS_SID_WRITE_DATA_BY_ID: // support write single frame
                if (first_byte >= 0x04 && first_byte <= 0x07)
                    return 0;
                break;
            case UDS_SID_IO_CONTROL_BY_ID: // only support one parameter(currentStatus) in this version
                if (first_byte >= 0x04 && first_byte <= 0x05)
                    return 0;
                break;
            case UDS_SID_REQUEST_XFER_EXIT:
                if (first_byte == 0x01)
                    return 0;
            default:
                if (first_byte >= 0x02 && first_byte <= 0x07)
                    return 0;
                break;
        }
        return INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT;
    }
    if (first_char == '1') {	// first frame 0x10-0x1f
        sid = frame.data[2];
        switch (sid) {
            case UDS_SID_DIAGNOSTIC_CONTROL:
            case UDS_SID_TESTER_PRESENT:
            case UDS_SID_SECURITY_ACCESS: // not support the field "securityAccessDataRecord" in this verison
            case UDS_SID_READ_DATA_BY_ID: // not support to read serval DIDs per request frame in this version
            case UDS_SID_IO_CONTROL_BY_ID: // not support to control multiple parameter per request frame in this version
                return INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT;
            case UDS_SID_WRITE_DATA_BY_ID: // support write multiple frame
                if (frame.data[1] >= 0x07 && frame.data[1] <= 0xFF) {
                    return 0;
                } else {
                    return INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT;
                }        
            default:
                return 0;
        }
    }
    if (first_char == '2') {	// consecutive frame 0x20-0x2f
        return 0;
    }
    if (first_char == '3') {	// flow control 0x30-0x32
        if (first_byte >= 0x30 && first_byte <= 0x32) {
            return 0;
        }     
    }
    return -1;
}

int isRequestSecurityAccessMember(unsigned int did) {
    for (int k = 0; k < DID_Security_21_Num; k++) {
        if (did == DID_Security_21[k])
            return 0;
    }
    return -1;
}

/* NRC 0x31 requestOutOfRange */
int isRequestOutOfRange(unsigned int did) {
    for (int i = 0; i < DID_No_Security_Num; i++) {
        if (did == DID_No_Security[i])
            return 0;
    }
    for (int j = 0; j < DID_Security_03_Num; j++) {
        if (did == DID_Security_03[j])
            return 0;
    }
    for (int k = 0; k < DID_Security_19_Num; k++) {
        if (did == DID_Security_19[k])
            return 0;
    }
    for (int k = 0; k < DID_Security_21_Num; k++) {
        if (did == DID_Security_21[k])
            return 0;
    }
    for (int l = 0; l < DID_IO_Control_Num; l++) {
        if (did == DID_IO_Control[l])
            return 0;
    }
    return REQUEST_OUT_OF_RANGE;
}

/* NRC 0x33 securityAccessDenied */
int isSecurityAccessDenied(unsigned int did) { 
    for (int i = 0; i < DID_No_Security_Num; i++) {
        if (did == DID_No_Security[i])
            return 0;
    }
    for (int j = 0; j < DID_Security_03_Num; j++) {
        if (did == DID_Security_03[j] && current_security_level != 0x00)
            return 0;
    }
    for (int k = 0; k < DID_Security_19_Num; k++) {
        if (did == DID_Security_19[k] && current_security_level == 0x19)
            return 0;
    }
    for (int k = 0; k < DID_Security_21_Num; k++) {
        if (did == DID_Security_21[k] && current_security_level == 0x21)
            return 0;
    }
    for (int l = 0; l < DID_IO_Control_Num; l++) {
        if (did == DID_IO_Control[l] && current_security_level != 0x00)
            return 0;
    }
    return SECURITY_ACCESS_DENIED;
}

/* NRC 0x7F serviceNotSupportedInActiveSession */
/* this function can only be used to the non-default session mode's services */
int isServiceNotSupportedInActiveSession() {
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    long currect_seconds = currentTime.tv_sec;
    long current_microseconds = currentTime.tv_usec;
    // printf("%d %d\n", currect_seconds, current_microseconds);
    // printf("%d %d\n", change_to_non_default_session_seconds, change_to_non_default_session_microseconds);
    // services not supported in the non-default session mode
    if (change_to_non_default_session_seconds == 0 || change_to_non_default_session_microseconds == 0)
        return SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION; 

    long delta_seconds = currect_seconds - change_to_non_default_session_seconds;
    long delta_microseconds = current_microseconds - change_to_non_default_session_microseconds;
    // printf("%d %d\n", delta_seconds, delta_microseconds);
    // not timeout
    if ((delta_seconds >= 0 && delta_seconds < S3Server_timer) || (delta_seconds == S3Server_timer && delta_microseconds <= 0))
        return 0;

    return SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION;
}
/********************************** NRC Handle End **********************************/


/********************************** Service Implement Start **********************************/
void session_mode_change(int can, struct can_frame frame) {
    struct can_frame resp;
    resp.can_id = diag_phy_resp_id;
    resp.can_dlc = 8;
    resp.data[0] = 0x06;
    resp.data[1] = frame.data[1] + 0x40;
    resp.data[2] = frame.data[2];
    resp.data[3] = 0x00;
    resp.data[4] = 0x32;
    resp.data[5] = 0x01;
    resp.data[6] = 0xF4;
    resp.data[7] = 0x00;
    write(can, &resp, CAN_MTU);
    if (current_session_mode != frame.data[2]) {
        current_session_mode = frame.data[2];
        reset_relevant_variables();
    }  
    if(current_session_mode == 0x01){   // init defauit session time
        change_to_non_default_session_seconds = 0;
        change_to_non_default_session_microseconds = 0;
    } else {                            // init non-defauit session time
        struct timeval currentTime;
        gettimeofday(&currentTime, NULL);
        change_to_non_default_session_seconds = currentTime.tv_sec;
        change_to_non_default_session_microseconds = currentTime.tv_usec;
    }
}

void tester_present(int can, struct can_frame frame) {
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    change_to_non_default_session_seconds = currentTime.tv_sec;
    change_to_non_default_session_microseconds = currentTime.tv_usec;

    int sf = frame.data[2];
    if (sf == 0x00) {	// must give a response
        struct can_frame resp;
        resp.can_id = diag_phy_resp_id;
        resp.can_dlc = 8;
        resp.data[0] = 0x02;
        resp.data[1] = frame.data[1] + 0x40;
        resp.data[2] = frame.data[2];
        resp.data[3] = 0x00;
        resp.data[4] = 0x00;
        resp.data[5] = 0x00;
        resp.data[6] = 0x00;
        resp.data[7] = 0x00;
        write(can, &resp, CAN_MTU);
        return;
    }
    if (sf == 0x80) {	// do not give a response
        return;
    }
}

void read_data_by_id(int can, struct can_frame frame) {
    // reset relevant buffer
    memset(gBuffer, 0, sizeof(gBuffer));
    gBufSize = 0;
    gBufLengthRemaining = 0;
    gBufCounter = 0;

    unsigned int did = get_did_from_frame(frame);
    
    if (isRequestSecurityAccessMember(did) == 0) {
        int nrc_33 = isSecurityAccessDenied(did);
        if (nrc_33 != 0) {
            send_negative_response(can, UDS_SID_READ_DATA_BY_ID, nrc_33);
            return;
        }
    }

    int nrc_31 = isRequestOutOfRange(did);
    if (nrc_31 != 0) {
        send_negative_response(can, UDS_SID_READ_DATA_BY_ID, nrc_31);
        return;
    }
 
    uint8_t str[256] = {0};
    str[0] = 0x62;
    str[1] = (uint8_t)((did & 0x0000ff00) >> 8);
    str[2] = (uint8_t)(did & 0x000000ff);
    for(int i=0; i<DID_NUM; i++) {
        if (pairs[i].key == did) {
            strncpy(&str[3], pairs[i].value, strlen(pairs[i].value));
            break;
        }
    }
    isotp_send_to(can, str, strlen(str));
    memset(str, 0, sizeof(str));
}

void write_data_by_id(int can, struct can_frame frame) {
    // reset relevant buffer
    memset(ggBuffer, 0, sizeof(ggBuffer));
    ggBufSize = 0;
    ggBufLengthRemaining = 0;
    ggBufCounter = 0;

    unsigned int did = get_did_from_frame(frame);
    int nrc_31 = isRequestOutOfRange(did);
    if (nrc_31 != 0) {
        send_negative_response(can, UDS_SID_WRITE_DATA_BY_ID, nrc_31);
        return;
    }
    int nrc_33 = isSecurityAccessDenied(did);
    if (nrc_33 != 0) {
        send_negative_response(can, UDS_SID_WRITE_DATA_BY_ID, nrc_33);
        return;
    }

    struct can_frame resp;
    char first_char = int2nibble(frame.data[0], 0);
    if (first_char == '0') {

        for(int i=0; i<DID_NUM; i++) {
            if(pairs[i].key == did) {
                memset(pairs[i].value, 0, sizeof(pairs[i].value));    // clear the original value
                strncpy(pairs[i].value, &frame.data[4], frame.data[0]-3);
            }
        }

        resp.can_id = diag_phy_resp_id;
        resp.can_dlc = 8;
        resp.data[0] = 0x03;
        resp.data[1] = frame.data[1] + 0x40;
        resp.data[2] = frame.data[2];
        resp.data[3] = frame.data[3];
        resp.data[4] = 0x00;
        resp.data[5] = 0x00;
        resp.data[6] = 0x00;
        resp.data[7] = 0x00;
        write(can, &resp, CAN_MTU);
    }
    if (first_char == '1') {
        ggBufSize = ((frame.data[0] & 0x0000000F) << 8) | frame.data[1];
        ggBufSize-=3;
        ggBufCounter = 0x21;
        ggSID = UDS_SID_WRITE_DATA_BY_ID;
        ggBufLengthRemaining = ggBufSize - 3;
        memset(ggBuffer, 0, sizeof(ggBuffer));   // clear the original value
        strncpy(ggBuffer, &frame.data[5], 3);
        
        tmp_store[0] = frame.data[2];   // SID
        tmp_store[1] = frame.data[3];   // DID_H
        tmp_store[2] = frame.data[4];   // DID_L

        resp.can_id = diag_phy_resp_id;
        resp.can_dlc = 8;
        resp.data[0] = 0x30;
        resp.data[1] = 0x00;
        resp.data[2] = 0x0F;
        resp.data[3] = 0x00;
        resp.data[4] = 0x00;
        resp.data[5] = 0x00;
        resp.data[6] = 0x00;
        resp.data[7] = 0x00;
        write(can, &resp, CAN_MTU);
    }
}

void security_access(int can, struct can_frame frame) {
    int sl = frame.data[2];
    uint8_t *seedp;
    uint8_t *keyp;
    struct can_frame resp;

    /* 27 first phase: request a 4-byte seed from server */
    if (sl == 0x03 || sl == 0x19 || sl == 0x21) {
		seedp = seed_generate(sl);
        resp.can_id = diag_phy_resp_id;
        resp.can_dlc = 8;
        resp.data[0] = 0x06;
        resp.data[1] = frame.data[1] + 0x40;
        resp.data[2] = frame.data[2];
        resp.data[3] = *seedp;
        resp.data[4] = *(seedp+1);
        resp.data[5] = *(seedp+2);
        resp.data[6] = *(seedp+3);
        resp.data[7] = 0x00;
        write(can, &resp, CAN_MTU);
        if (sl != current_security_level) {
            if (sl == 0x03) {
                current_seed_3 = seedp;
                current_security_phase_3 = 1;
            }
            if (sl == 0x19) {
                current_seed_19 = seedp;
                current_security_phase_19 = 1;
            }
            if (sl == 0x21) {
                current_seed_21 = seedp;
                current_security_phase_21 = 1;
            }
        }
        return;
    }
    if (sl == 0x04 || sl == 0x1A || sl == 0x22) {
        /* must request seed firstly */
        if ((sl == 0x04 && current_security_phase_3 != 1) || (sl == 0x1A && current_security_phase_19 != 1) || (sl == 0x22 && current_security_phase_21 != 1)) {
            send_negative_response(can, UDS_SID_SECURITY_ACCESS, REQUEST_SEQUENCE_ERROR);
            return;
        }

        /* calculate key */
        if (sl == 0x04 && current_seed_3 != NULL && current_security_phase_3 ==1) {
            keyp = security_algorithm(current_seed_3, sl);
            // printf("%02x %02x %02x %02x\n", keyp[0], keyp[1], keyp[2], keyp[3]);
        }    
        if (sl == 0x1A && current_seed_19 != NULL && current_security_phase_19 ==1) {
            keyp = security_algorithm(current_seed_19, sl);
        } 
        if (sl == 0x22 && current_seed_21 != NULL && current_security_phase_21 ==1) {
            keyp = security_algorithm(current_seed_21, sl);
        } 
        /* determine the passed key is right or not */
        if (*keyp == frame.data[3] && *(keyp+1) == frame.data[4] \
                && *(keyp+2) == frame.data[5] && *(keyp+3) == frame.data[6]) {  // key is correct
            resp.can_id = diag_phy_resp_id;
            resp.can_dlc = 8;
            resp.data[0] = 0x02;
            resp.data[1] = frame.data[1] + 0x40;
            resp.data[2] = frame.data[2];
            resp.data[3] = 0x00;
            resp.data[4] = 0x00;
            resp.data[5] = 0x00;
            resp.data[6] = 0x00;
            resp.data[7] = 0x00;
            write(can, &resp, CAN_MTU);
            if (sl == 0x04) {
                current_security_level = sl-1;
                current_security_phase_3 = 2;
            }
            if (sl == 0x1A) {
                current_security_level = sl-1;
                current_security_phase_19 = 2;
                security_access_error_attempt = 0;
            }
            if (sl == 0x22) {
                current_security_level = sl-1;
                current_security_phase_21 = 2;
                security_access_error_attempt = 0;
            }
            security_access_lock_time = 0;
        } else {    // key is incorrect
            send_negative_response(can, UDS_SID_SECURITY_ACCESS, INVALID_KEY);
            if (sl == 0x04) {
                current_security_phase_3 = 0;
            }
            if (sl == 0x1A) {
                current_security_phase_19 = 0;
                security_access_error_attempt += 1;
            }
            if (sl == 0x22) {
                current_security_phase_21 = 0;
                security_access_error_attempt += 1;
            }
        }
        /* determine the service 27 error attempt number is exceed or not */
        if (security_access_error_attempt >= SECURITY_ACCESS_ERROR_LIMIT_NUM) {
            send_negative_response(can, UDS_SID_SECURITY_ACCESS, EXCEED_NUMBER_OF_ATTEMPTS);
            // store currect time
            security_access_lock_time = time(NULL);
        }
        /* reset the global variables current_seed_* */
        if (sl == 0x04) {
            current_seed_3 = NULL;
        }
        if (sl == 0x1A) {
            current_seed_19 = NULL;
        }
        if (sl == 0x22) {
            current_seed_21 = NULL;
        }
        return;
    }
}

void io_control_by_did(int can, struct can_frame frame) {
    unsigned int did = get_did_from_frame(frame);
    int nrc_31 = isRequestOutOfRange(did);
    if (nrc_31 != 0) {
        send_negative_response(can, UDS_SID_IO_CONTROL_BY_ID, nrc_31);
        return;
    }
    int nrc_33 = isSecurityAccessDenied(did);
    if (nrc_33 != 0) {
        send_negative_response(can, UDS_SID_IO_CONTROL_BY_ID, nrc_33);
        return;
    }

    int iocp = frame.data[4];
    int cs = frame.data[5];
    switch (iocp) {
        case 0x03: // only support function "shortTermAdjustment" in this version. 
            if (did == 0xF081) {
                if (cs<=0 || cs >= 7) {
                    send_negative_response(can, UDS_SID_IO_CONTROL_BY_ID, REQUEST_OUT_OF_RANGE);
                    return;
                }
                struct timeval currentTime;
                gettimeofday(&currentTime, NULL);
                io_control_seconds = currentTime.tv_sec;
                io_control_microseconds = currentTime.tv_usec;
                tmp_store[0] = did & 0x000000FF;
                tmp_store[1] = (did & 0x0000FF00) >> 8;
                tmp_store[2] = cs;
                io_control_id_flag = 1;
            }
            return;
        default:    // do nothing
            return;
    }
}

void request_download_or_upload(int can, struct can_frame frame, int sid) {
    u_int8_t dataFormatIdentifier = frame.data[2];
    u_int8_t addressAndLengthFormatIdentifier = frame.data[3];
    // high 4 bits is memoryAddressLength, low 4 bits is memorySizeLength
    u_int8_t memoryAddressLength = (addressAndLengthFormatIdentifier & 0xF0) >> 4;
    u_int8_t memorySizeLength = addressAndLengthFormatIdentifier & 0x0F;
    u_int32_t memoryAddress = 0;
    u_int32_t memorySize = 0;
    // nrc13 check
    if (frame.data[0] != 3+memoryAddressLength+memorySizeLength) {
        send_negative_response(can, sid, INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT);
        return;
    }
    if (memoryAddressLength > 2 || memorySizeLength > 2) {
        send_negative_response(can, sid, REQUEST_OUT_OF_RANGE);
        return;
    }
    // get memoryAddress and memorySize 
    for (int i = 0; i < memoryAddressLength; i++) {
        memoryAddress = memoryAddress << 8;
        memoryAddress += frame.data[4+i];
    }
    for (int i = 0; i < memorySizeLength; i++) {
        memorySize = memorySize << 8;
        memorySize += frame.data[4+memoryAddressLength+i];
    }
    if (memoryAddress + memorySize >= SPACE_SIZE) {
        send_negative_response(can, sid, REQUEST_OUT_OF_RANGE);
        return;
    }
    req_transfer_data_add = memoryAddress;
    req_transfer_data_len = memorySize;
    
    req_transfer_type = sid;
    // Calculate the number of data blocks required (divide by 127 to round up the result)
    req_transfer_block_num = (req_transfer_data_len + 127 - 1) / 127;

    struct can_frame resp;
    resp.can_id = diag_phy_resp_id;
    resp.can_dlc = 8;
    resp.data[0] = 0x04;
    resp.data[1] = frame.data[1] + 0x40;
    resp.data[2] = 0x20;    // lengthFormatIdentifier
    resp.data[3] = 0x00;    // maximumNumberBlockLength: 0x0081
    resp.data[4] = 0x81;
    resp.data[5] = 0x00;
    resp.data[6] = 0x00;
    resp.data[7] = 0x00;
    write(can, &resp, CAN_MTU);
}

void transfer_data(int can, struct can_frame frame) {
    char first_char = int2nibble(frame.data[0], 0);
    u_int8_t sequenceNumber = first_char == '0' ? frame.data[2]: frame.data[3];
    u_int8_t buffer[129] = {0};

    if (sequenceNumber > req_transfer_block_num || sequenceNumber == 0) {
        send_negative_response(can, UDS_SID_TRANSFER_DATA, REQUEST_OUT_OF_RANGE);
        return;
    }
    if (sequenceNumber != req_transfer_block_counter+1 && sequenceNumber != req_transfer_block_counter) {
        send_negative_response(can, UDS_SID_TRANSFER_DATA, REQUEST_SEQUENCE_ERROR);
        return;
    }
    if (first_char == '0') {
        if (sequenceNumber == req_transfer_block_counter) {
            req_transfer_block_counter--;
        }
    }
    
    
    if (req_transfer_type == UDS_SID_REQUEST_DOWNLOAD) {
        int max_block_len = req_transfer_data_len > 127 ? 127 : req_transfer_data_len;
        int remain_block_data_len = req_transfer_data_len - (sequenceNumber-1)*max_block_len;
        remain_block_data_len = remain_block_data_len > 127 ? 127 : remain_block_data_len;
        struct can_frame resp;
        if (first_char == '0') {
            // reset taget memory space
            memset(&firmwareSpace[req_transfer_data_add + (sequenceNumber-1)*max_block_len], 0, max_block_len);

            resp.can_id = diag_phy_resp_id;
            resp.can_dlc = 8;
            resp.data[0] = 0x02;
            resp.data[1] = frame.data[1] + 0x40;
            resp.data[2] = ++req_transfer_block_counter;
            resp.data[3] = 0x00;
            resp.data[4] = 0x00;
            resp.data[5] = 0x00;
            resp.data[6] = 0x00;
            resp.data[7] = 0x00;
            write(can, &resp, CAN_MTU);
        }
        if (first_char == '1') {
            ggBufSize = ((frame.data[0] & 0x0000000F) << 8) | frame.data[1];
            ggBufSize -= 2;
            if (ggBufSize > remain_block_data_len) {
                send_negative_response(can, UDS_SID_TRANSFER_DATA, TRANSFER_DATA_SUSPENDED);
                ggBufSize = 0;
                return;
            }
            ggBufCounter = 0x21;
            ggSID = UDS_SID_TRANSFER_DATA;
            ggBufLengthRemaining = ggBufSize - 4;
            memset(ggBuffer, 0, sizeof(ggBuffer));   // clear the original value
            memcpy(ggBuffer, &frame.data[4], 4);

            tmp_store[0] = frame.data[2];   // SID

            resp.can_id = diag_phy_resp_id;
            resp.can_dlc = 8;
            resp.data[0] = 0x30;
            resp.data[1] = 0x00;
            resp.data[2] = 0x0F;
            resp.data[3] = 0x00;
            resp.data[4] = 0x00;
            resp.data[5] = 0x00;
            resp.data[6] = 0x00;
            resp.data[7] = 0x00;
            write(can, &resp, CAN_MTU);
        }
    }

    if (req_transfer_type == UDS_SID_REQUEST_UPLOAD) {
        int max_block_len = req_transfer_data_len > 127 ? 127 : req_transfer_data_len;
        int block_len = (req_transfer_data_len - (sequenceNumber-1)*127) > 127 ? max_block_len : (req_transfer_data_len - (sequenceNumber-1)*127);
        memcpy(buffer+2, &firmwareSpace[req_transfer_data_add + (sequenceNumber-1)*127], block_len);

        buffer[0] = frame.data[1] + 0x40;
        buffer[1] = sequenceNumber;
        isotp_send_to(can, buffer, block_len + 2);
        req_transfer_block_counter++;
    }
}

void xfer_exit(int can, struct can_frame frame) {
    struct can_frame resp;
    resp.can_id = diag_phy_resp_id;
    resp.can_dlc = 8;
    resp.data[0] = 0x01;
    resp.data[1] = frame.data[1] + 0x40;
    resp.data[2] = 0x00;
    resp.data[3] = 0x00;
    resp.data[4] = 0x00;
    resp.data[5] = 0x00;
    resp.data[6] = 0x00;
    resp.data[7] = 0x00;
    write(can, &resp, CAN_MTU);
    // reset
    req_transfer_data_add = 0;
    req_transfer_data_len = 0;
    req_transfer_block_num = 0;
    req_transfer_block_counter = 0;
    req_transfer_type = 0x00;
}

/********************************** Service Implement End **********************************/


int isSFExisted(int can, int sid, int sf) {
    int nrc_12 = isSubFunctionSupported(sid, sf);
    if (nrc_12 != 0 ) {
        send_negative_response(can, sid, nrc_12);
        return -1;
    }
    return 0;
}

int isNonDefaultModeTimeout(int can, int sid) {
    int nrc_7F = isServiceNotSupportedInActiveSession();
    if (nrc_7F != 0) {
        current_session_mode = 0x01;
        reset_relevant_variables();
        send_negative_response(can, sid, nrc_7F);
        return -1;
    }
    return 0 ;
}

void handle_pkt(int can, struct can_frame frame) {
    // print the received frame
    // printf("Pkt: %02X#", frame.can_id);
    // for (int i = 0; i < frame.can_dlc; i++) {
    //     printf("%02X ", frame.data[i]);
    // }
    // printf("\n");

    /* used for $2F */
    if (io_control_id_flag == 1) { 
        struct timeval currentTime;
        gettimeofday(&currentTime, NULL);
        long delta_seconds = currentTime.tv_sec - io_control_seconds;
        long delta_microseconds = currentTime.tv_usec - io_control_microseconds;
        // printf("%ld %ld\n", delta_seconds, delta_microseconds);
        // timeout
        if (!(delta_seconds == 0 && delta_microseconds >= 0 && delta_microseconds <= 999999)) {
            // reset variables
            memset(tmp_store, 0, sizeof(tmp_store));
            io_control_seconds = 0;
            io_control_microseconds = 0;
            io_control_id_flag = 0;
            return;
        }
        
        unsigned int io_did = (tmp_store[1] << 8) | tmp_store[0];
        if (io_did == 0xF081) {
            if (frame.can_id != 0x165) {
                return;
            }
            frame.data[0] = tmp_store[2]*40;
            for(int i=0; i<10; i++) {
                write(can, &frame, CAN_MTU);
                udelay(20*1000);    // 20ms
            }
        }

        // add other situations of DID for $2F here.

        // reset variables
        memset(tmp_store, 0, sizeof(tmp_store));
        io_control_seconds = 0;
        io_control_microseconds = 0;
        io_control_id_flag = 0;
    }

    /* DO NOT RECEIVE OTHER CANID */
    if (frame.can_id != diag_func_req_id && frame.can_id != diag_phy_req_id) {
        return;
    }

    /* GET SID & SF */
    char first_char = int2nibble(frame.data[0], 0);
    int sid, sf;
    if (first_char == '0') {
        sid = frame.data[1];
        sf = frame.data[2];
    }
    if (first_char == '1') {
        sid = frame.data[2];
        sf = frame.data[3];
    }

    // NRC 0x13
    int nrc_13 = isIncorrectMessageLengthOrInvalidFormat(frame);
    if (nrc_13 == -1)   // do not give a response
        return;
    if (nrc_13 != 0) {
        send_negative_response(can, sid, nrc_13);
        return;
    }  

    if (first_char == '0' || first_char == '1') {
        switch (sid) {
            case UDS_SID_DIAGNOSTIC_CONTROL:    // SID 0x10
                if (isSFExisted(can, sid, sf) == -1) 
                    return;
                session_mode_change(can, frame);
                return;
            case UDS_SID_TESTER_PRESENT:        // SID 0x3E
                if (current_session_mode != 0x01) { 
                    if (isSFExisted(can, sid, sf) == -1) 
                        return;
                    tester_present(can, frame);
                    return;
                } else {    // default session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } 
            case UDS_SID_READ_DATA_BY_ID:       // SID 0x22
                if (isSFExisted(can, sid, sf) == -1) 
                    return;
                read_data_by_id(can, frame);
                return;
            case UDS_SID_WRITE_DATA_BY_ID:      // SID 0x2E
                if (current_session_mode != 0x01) { // only support SID 0x2E in non-default session mode
                    if (isNonDefaultModeTimeout(can, sid) == -1) 
                        return;
                    if (isSFExisted(can, sid, sf) == -1) 
                        return;
                    write_data_by_id(can, frame);
                    return;
                } else {    // default session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                }     
            case UDS_SID_SECURITY_ACCESS:       // SID 0x27
                if (current_session_mode != 0x01) { // only support SID 0x27 in non-default session mode
                    // printf("## current_session_mode = %#x\n", current_session_mode);
                    if (isNonDefaultModeTimeout(can, sid) == -1) 
                        return;
                    if (isSFExisted(can, sid, sf) == -1) 
                        return;
                    if (security_access_lock_time != 0 && (time(NULL) - security_access_lock_time) < SECURITY_ACCESS_LOCK_DELAY) {
                        send_negative_response(can, sid, REQUIRED_TIME_DELAY_NOT_EXPIRED);
                        return;
                    }
                    security_access(can, frame);
                    return;
                } else {    // default session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } 
            case UDS_SID_IO_CONTROL_BY_ID:      // SID 0X2F
                if (current_session_mode != 0x01) { // only support SID 0x2F in non-default session mode
                    if (isNonDefaultModeTimeout(can, sid) == -1) 
                        return;
                    if (isSFExisted(can, sid, sf) == -1) 
                        return;
                    io_control_by_did(can, frame);
                    return;
                } else {    // default session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } 
            case UDS_SID_REQUEST_DOWNLOAD:
            case UDS_SID_REQUEST_UPLOAD:      // SID 0x34 or 0x35
                if (current_session_mode != 0x02) {
                    // MUST in programming session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } else if (current_security_level == 0x00) {
                    // MUST unlock the security access
                    send_negative_response(can, sid, SECURITY_ACCESS_DENIED);
                    return;
                } else if (req_transfer_type != 0) {
                    send_negative_response(can, sid, CONDITIONS_NOT_CORRECT);
                    return;
                } else {
                    request_download_or_upload(can, frame, sid);
                    return;
                }
            case UDS_SID_TRANSFER_DATA:         // SID 0x36
                if (current_session_mode != 0x02) {
                    // MUST in programming session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } else if (current_security_level == 0x00) {
                    // MUST unlock the security access
                    send_negative_response(can, sid, SECURITY_ACCESS_DENIED);
                    return;
                } else if (req_transfer_type != 0x34 && req_transfer_type != 0x35) {
                    send_negative_response(can, sid, REQUEST_SEQUENCE_ERROR);
                    return;
                } else {
                    transfer_data(can, frame);
                    return;
                }
            case UDS_SID_REQUEST_XFER_EXIT:
                if (current_session_mode != 0x02) {
                    // MUST in programming session mode
                    send_negative_response(can, sid, SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
                    return;
                } else if (req_transfer_type != 0x34 && req_transfer_type != 0x35 || (req_transfer_block_counter != req_transfer_block_num)) {
                    send_negative_response(can, sid, REQUEST_SEQUENCE_ERROR);
                    return;
                } else {
                    xfer_exit(can, frame);
                    return;
                }

            default:
                send_negative_response(can, sid, SERVICE_NOT_SUPPORTED);
                return;
        }
    }

    if (first_char == '2') {
        if (ggBufLengthRemaining > 0) { 
            if (isNonDefaultModeTimeout(can, tmp_store[0]) == -1) {
                return;
            }

            if (ggBufCounter != frame.data[0]) {
                memset(ggBuffer, 0, sizeof(ggBuffer));
                return;
            }

            if (ggBufLengthRemaining > 7) {
                memcpy(ggBuffer + (ggBufSize - ggBufLengthRemaining), &frame.data[1], 7);
                ggBufCounter++;
                if (ggBufCounter == 0x30)
                    ggBufCounter = 0x20;
                ggBufLengthRemaining -= 7;      
            } else {
                memcpy(ggBuffer + (ggBufSize - ggBufLengthRemaining), &frame.data[1], ggBufLengthRemaining);
                ggBufLengthRemaining = 0;
                if (ggSID == UDS_SID_WRITE_DATA_BY_ID) {
                    unsigned char bytes[] = {tmp_store[1], tmp_store[2]};   //	two bytes of DID
                    unsigned int did = (bytes[0] << 8) | bytes[1];          //	DID hex int value
                    for(int i=0; i<DID_NUM; i++) {
                        if(pairs[i].key == did) {
                            memset(pairs[i].value, 0, sizeof(pairs[i].value));    // clear the original value
                            strncpy(pairs[i].value, ggBuffer, strlen(ggBuffer));
                        }
                    }
                    struct can_frame resp;
                    resp.can_id = diag_phy_resp_id;
                    resp.can_dlc = 8;
                    resp.data[0] = 0x03;
                    resp.data[1] = tmp_store[0] + 0x40;
                    resp.data[2] = tmp_store[1];
                    resp.data[3] = tmp_store[2];
                    resp.data[4] = 0x00;
                    resp.data[5] = 0x00;
                    resp.data[6] = 0x00;
                    resp.data[7] = 0x00;
                    write(can, &resp, CAN_MTU);
                    memset(tmp_store, 0, sizeof(tmp_store));
                    memset(ggBuffer, 0, sizeof(ggBuffer));
                }
                if (ggSID == UDS_SID_TRANSFER_DATA) {
                    memcpy(ggBuffer + (ggBufSize - ggBufLengthRemaining), &frame.data[1], ggBufLengthRemaining);
                    int max_block_len = req_transfer_data_len > 127 ? 127 : req_transfer_data_len;
                    int start_add = req_transfer_data_add + req_transfer_block_counter*max_block_len;
                    memcpy(&firmwareSpace[start_add], ggBuffer, max_block_len);

                    struct can_frame resp;
                    resp.can_id = diag_phy_resp_id;
                    resp.can_dlc = 8;
                    resp.data[0] = 0x02;
                    resp.data[1] = tmp_store[0] + 0x40;
                    resp.data[2] = ++req_transfer_block_counter;
                    resp.data[3] = 0x00;
                    resp.data[4] = 0x00;
                    resp.data[5] = 0x00;
                    resp.data[6] = 0x00;
                    resp.data[7] = 0x00;
                    write(can, &resp, CAN_MTU);
                    memset(ggBuffer, 0, sizeof(ggBuffer));
                }
            }
        }
        return;
    }

    if (first_char == '3') {
        if (flow_control_flag) {   // 0-false 1-true
            // uint8_t FS = frame.data[0] & 0x0F;
            // uint8_t BS = frame.data[1];
            uint8_t STmin = frame.data[2];

            // fs = FS;
            // bs = BS;
            if (STmin>0 && STmin<=0x7F) {   // 0x0-0x7F ms
                st_min = STmin*1000;
            } else if (STmin>=0xF1 && STmin<=0xF9) {    // 100-900 us
                st_min = (STmin & 0x0F) * 100;
            } else {                        // 1 ms
                st_min = 1000;
            }

            flow_control_push_to(can);
            flow_control_flag = 0;
        }

    }
}

void help(cJSON *root) {
    char supported_ecu[256] = {0};

    cJSON *obj = root->child;
    while (obj) {
        strncat(supported_ecu, obj->string, strlen(obj->string));
        strncat(supported_ecu, " " , 1);
        obj = obj->next;
    }

    char *pos = strstr(supported_ecu, "CURRENT_ECU ");
    int left_len = strlen(pos+strlen("CURRENT_ECU "));
    memcpy(pos, pos+strlen("CURRENT_ECU "), strlen(pos+strlen("CURRENT_ECU ")));
    memset(pos+left_len, 0, strlen("CURRENT_ECU "));

    printf("\nuds-server-simulator %s\n", version);
    printf("Author: Honinbon\n\n");
    printf("Usage: \n\tuds-server-simulator [options] <CAN interface> \n\n");
    printf("Options:\n");
    printf("\t-e <ecu name>\tecu name: %s\n", supported_ecu);
    printf("\t-h\t\tprint this help menu\n\n");
    printf("Examples:\n");
    printf("\t./uds-server-simulator -e TBOX can0\n\n");
 }

cJSON *read_config(){
    FILE *file = NULL;
    file = fopen(CONFIG_JSON_FILE, "r");
    if (file == NULL) {
        printf("## OPEN CONFIG FAIL ##\n");
        exit(1);
    }
    struct stat statbuf;
    stat(CONFIG_JSON_FILE, &statbuf);
    int fileSize = statbuf.st_size;
    char *jsonStr = (char *)malloc(sizeof(char) * fileSize + 1);
    memset(jsonStr, 0, fileSize + 1);
    int size = fread(jsonStr, sizeof(char), fileSize, file);
    if (size == 0) {
        printf("## READ CONFIG FAIL ##\n");
        exit(1);
    }
    fclose(file);

    cJSON *root = cJSON_Parse(jsonStr);
    if (!root) {
        const char *err = cJSON_GetErrorPtr();
        printf("Error before: [%s]\n", err);
        free((void *)err);
        free(jsonStr);
        exit(1);
    }
    free(jsonStr);
    return root;
}

int main(int argc, char *argv[]) {  // referred to Craig Smith's uds-server.
    int opt, ret;
    int can;
    int nbytes;
    struct ifreq ifr;
    struct sockaddr_can addr;
    struct iovec iov;
    struct msghdr msg;
    struct can_frame frame;
    char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
    struct timeval timeo;
    fd_set rdfs;
    char *ecu;

    cJSON *root = read_config();

    while ((opt = getopt(argc, argv, "e:h")) != -1) {
        switch(opt) {
            case 'e':
                ecu = optarg;
                break;
            case 'h':
            default:
                help(root);
                exit(0);
        }
    }

    if(argv[optind] == NULL){
        help(root);
        exit(0);
    }
        
    uds_server_init(root, ecu);

    // Create a new raw CAN socket
    can = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can < 0)
        printf("Couldn't create raw socket");
    
    addr.can_family = AF_CAN;
    memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_name, argv[optind], strlen(argv[optind]));
    if (ioctl(can, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    addr.can_ifindex = ifr.ifr_ifindex;
    
    if (bind(can, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    iov.iov_base = &frame;
    iov.iov_len = sizeof(frame);
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &ctrlmsg;
    msg.msg_controllen = sizeof(ctrlmsg);
    msg.msg_flags = 0;

    int running = 1;
    while (running) {
        FD_ZERO(&rdfs);
        FD_SET(can, &rdfs);

        timeo.tv_sec = 0;
        timeo.tv_usec = 10000 * 20; // 20 ms

        if ((ret = select(can + 1, &rdfs, NULL, NULL, &timeo)) < 0) {
            running = 0;
            continue;
        }

        if (FD_ISSET(can, &rdfs)) {
            nbytes = recvmsg(can, &msg, 0);
            if (nbytes < 0) {
                perror("read");
                return 1;
            }
            if ((size_t)nbytes != CAN_MTU) {
                fprintf(stderr, "read: incomplete CAN frame\n");
                return 1;
            }
            handle_pkt(can, frame);
        }
    }

    printf("Got Interrupt.  Shutting down gracefully\n");
}
