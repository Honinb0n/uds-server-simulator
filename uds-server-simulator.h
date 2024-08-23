/* uds-server-simulator init config json file */
#define CONFIG_JSON_FILE    "config.json"
  
/* UDS SIDs */
#define UDS_SID_DIAGNOSTIC_CONTROL        0x10
#define UDS_SID_ECU_RESET                 0x11
#define UDS_SID_GM_READ_FAILURE_RECORD    0x12
#define UDS_SID_CLEAR_DTC                 0x14
#define UDS_SID_READ_DTC                  0x19
#define UDS_SID_GM_READ_DID_BY_ID         0x1A
#define UDS_SID_RESTART_COMMUNICATIONS    0x20 
#define UDS_SID_READ_DATA_BY_ID           0x22
#define UDS_SID_READ_MEM_BY_ADDRESS       0x23
#define UDS_SID_READ_SCALING_BY_ID        0x24
#define UDS_SID_SECURITY_ACCESS           0x27
#define UDS_SID_COMMUNICATION_CONTROL     0x28 
#define UDS_SID_READ_DATA_BY_ID_PERIODIC  0x2A
#define UDS_SID_DEFINE_DATA_ID            0x2C
#define UDS_SID_WRITE_DATA_BY_ID          0x2E
#define UDS_SID_IO_CONTROL_BY_ID          0x2F
#define UDS_SID_ROUTINE_CONTROL           0x31
#define UDS_SID_REQUEST_DOWNLOAD          0x34
#define UDS_SID_REQUEST_UPLOAD            0x35
#define UDS_SID_TRANSFER_DATA             0x36
#define UDS_SID_REQUEST_XFER_EXIT         0x37
#define UDS_SID_REQUEST_XFER_FILE         0x38
#define UDS_SID_WRITE_MEM_BY_ADDRESS      0x3D
#define UDS_SID_TESTER_PRESENT            0x3E
#define UDS_SID_ACCESS_TIMING             0x83
#define UDS_SID_SECURED_DATA_TRANS        0x84
#define UDS_SID_CONTROL_DTC_SETTINGS      0x85
#define UDS_SID_RESPONSE_ON_EVENT         0x86
#define UDS_SID_LINK_CONTROL              0x87
#define UDS_SID_GM_PROGRAMMED_STATE       0xA2
#define UDS_SID_GM_PROGRAMMING_MODE       0xA5
#define UDS_SID_GM_READ_DIAG_INFO         0xA9
#define UDS_SID_GM_READ_DATA_BY_ID        0xAA
#define UDS_SID_GM_DEVICE_CONTROL         0xAE

/* NRC Supported */
#define SERVICE_NOT_SUPPORTED	                    0x11
#define SUB_FUNCTION_NOT_SUPPORTED	                0x12
#define INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT	0x13
#define CONDITIONS_NOT_CORRECT	                    0x22
#define REQUEST_SEQUENCE_ERROR	                    0x24
#define REQUEST_OUT_OF_RANGE	                    0x31
#define SECURITY_ACCESS_DENIED	                    0x33
#define INVALID_KEY	                                0x35
#define EXCEED_NUMBER_OF_ATTEMPTS	                0x36
#define REQUIRED_TIME_DELAY_NOT_EXPIRED	            0x37
#define TRANSFER_DATA_SUSPENDED	                    0x71
#define SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION	    0x7F

/* Others */
#define SECURITY_ACCESS_ERROR_LIMIT_NUM     3
#define SECURITY_ACCESS_LOCK_DELAY          5