#ifndef _APP_TYPES_H_
#define _APP_TYPES_H_

#define BUFFER_SIZE     4096
#define MAX_MSG_SIZE    4096

#define VERBOSE         1

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

typedef struct {
    char *bgp_serv_addr;
    int bgp_serv_port;
    char *pctrlr_serv_addr;
    int pctrlr_serv_port;
} net_conf_t;

#endif
