#ifndef _APP_TYPES_H_
#define _APP_TYPES_H_

#include "shared_types.h"
#include "uthash.h"

#define BUFFER_SIZE     4096
#define MAX_MSG_SIZE    4096

#define VERBOSE         1

#define GEN_SIG_FILE    "sig"
#define RESULT_FILE     "result"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

typedef struct {
    char *bgp_serv_addr;
    int bgp_serv_port;
    char *pctrlr_serv_addr;
    int pctrlr_serv_port;
} net_conf_t;

typedef struct {
    char ip_num;
    char **ips;
} as_ips_t;

typedef struct {
    uint32_t as_size;
    uint32_t *as_id_2_n;
    as_ips_t *as_ips;
    as_policy_t *as_policies;
} as_cfg_t;

typedef struct {
    char *prefix;   // key
    char *vnh;      // value
    UT_hash_handle hh;
} vnh_map_t;

typedef struct {
    uint32_t crnt_vnh;
    vnh_map_t *vnh_map;
} vnh_state_t;

// message processing related states
typedef struct {
    uint32_t as_size;
    int *pctrlr_sfds;
    as_ips_t *as_ips;
    vnh_state_t vnh_states;
} msg_state_t;

#endif
