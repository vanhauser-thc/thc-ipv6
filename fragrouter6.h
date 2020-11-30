// Define protocol types for AF_INET packets
typedef enum {
  IP_PROTOCOL_ICMP = 1,
  IP_PROTOCOL_IGMP = 2,
  IP_PROTOCOL_TCP = 6,
  IP_PROTOCOL_UDP = 17,
  IP_PROTOCOL_FRAG = 44,
  IP_PROTOCOL_ICMP6 = 58,
  IP_PROTOCOL_EH_DST = 60
} ip_protocol_enum;

// Define log levels using with log_message function
typedef enum {
  LOG_DEBUG = 0,
  LOG_NOTICE = 1,
  LOG_WARNING = 2,
  LOG_ERROR = 3
} log_level_enum;

// Define exit codes used in the application
typedef enum {
  EXITCODE_OK = 0,
  EXITCODE_NO_MEMORY,
  EXITCODE_NFQ_OPEN_FAILED,
  EXITCODE_NFQ_CLOSE_FAILED,
  EXITCODE_NFQ_BIND_FAILED,
  EXITCODE_NFQ_UNBIND_FAILED,
  EXITCODE_NFQ_CREATEQUEUE_FAILED,
  EXITCODE_NFQ_DESTROYQUEUE_FAILED,
  EXITCODE_NFQ_SETMODE_FAILED

} exit_code_enum;
