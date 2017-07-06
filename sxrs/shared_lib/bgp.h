#ifndef _BGP_H_
#define _BGP_H_

#define ROUTE_FIELD             8
#define ROUTE_DELIMITER_CHAR    ','
#define ROUTE_DELIMITER_STR     ","
#define AS_PATH_DELIMITER_CHAR  ' '
#define AS_PATH_DELIMITER_STR   " "

// oprt_type
#define ANNOUNCE                1
#define WITHDRAW                2

// export_policy_class
#define CUSTOMER                0
#define PEER                    1
#define PROVIDER                2
#define POLICY_CLASS_NUM        3

#define TO_BE_DEL               -1

#include <stdint.h>
#include "uthash.h"

// base route type
typedef struct {
    int length;
    int *asns;
} as_path_t;

typedef struct {
    char *prefix;
    char *neighbor;
    char *next_hop;
    char *origin;
    as_path_t as_path;
    char *communities;
    int med;
    int atomic_aggregate;
} route_t;

// route list type
// for routes containing the same prefix
typedef struct _route_node route_node_t;

struct _route_node {
    union {
        uint8_t is_selected;
        uint8_t oprt_type;
    } flag;
    uint32_t advertiser_asn;
    uint32_t advertiser_asid;
    route_t *route;
    route_node_t *prev;
    route_node_t *next;
};

typedef struct {
    int route_num;
    route_node_t *head;
} route_list_t;

// set type
typedef struct _set_node_t set_node_t;

struct _set_node_t {
    uint32_t part_asn;
    set_node_t *prev;
    set_node_t *next;
};

typedef struct {
    int set_size;
    set_node_t *head;
} set_t;

// rib type
typedef struct _rib_map rib_map_t;

struct _rib_map {
    char *key;
    set_t *set;         // augmented reachability for SDN policies
    route_list_t *rl;
    UT_hash_handle hh;
};

typedef struct _rs_inner_msg rs_inner_msg_t;

struct _rs_inner_msg {
    uint8_t oprt_type;
    uint32_t src_asn;   // next hop
    route_t *src_route;
    rs_inner_msg_t *prev;
    rs_inner_msg_t *next;
};

typedef struct {
    uint32_t msg_size;
    uint32_t asn;
    uint8_t oprt_type;
    uint8_t route[];
} bgp_enc_msg_t;

typedef struct {
    uint32_t asn;
    uint8_t oprt_type;
    route_t *p_route;
} bgp_dec_msg_t;

typedef struct {
    uint32_t asn;
    uint8_t oprt_type;
    char *prefix;
    char *next_hop;
    as_path_t as_path;
} resp_dec_msg_t;

typedef struct {
    uint32_t asn;
    char *prefix;
    uint32_t set_size;
    uint32_t *set;
} resp_dec_set_msg_t;

char *my_strdup(const char *s);
void free_route_ptr(route_t **pp_route);
void reset_route(route_t *p_route);
void free_resp_dec_set_msg(resp_dec_set_msg_t *p_resp_dec_set_msg);
void free_resp_dec_msg(resp_dec_msg_t *p_resp_dec_msg);
void print_route(route_t *p_route);
void parse_route_from_file(route_t **pp_route, char *p_s_route);
int parse_route_from_stream(route_t **pp_route, uint8_t *p_s_route);
void route_cpy(route_t **dst_route, uint32_t *src_asn, const route_t *src_route);
int get_route_size(route_t *r);
int write_route_to_stream(uint8_t **pp_msg, route_t *input);
int write_route_to_existed_stream(uint8_t *route, route_t *input);
int parse_resp_from_stream(resp_dec_msg_t **pp_resp_dec_msgs, size_t *p_resp_msg_num, resp_dec_set_msg_t **pp_resp_dec_set_msgs, size_t *p_resp_set_msg_num, uint8_t *p_msg);
int write_resp_to_stream(uint8_t **pp_msg, resp_dec_msg_t *p_resp_dec_msgs, size_t resp_msg_num, resp_dec_set_msg_t *p_resp_dec_set_msgs, size_t resp_set_msg_num);
route_node_t* rl_get_selected_route_node(route_list_t *p_rl);
void rl_add_route(route_list_t **pp_rl, uint32_t src_asn, uint32_t src_asid, route_t *src_route, uint8_t *selection_policy);
void rl_del_route(route_list_t **pp_rl, uint32_t src_asn, route_t *src_route, uint8_t *selection_policy, route_node_t *p_old_best_rn);
void execute_export_policy(rs_inner_msg_t **pp_inner_msgs, uint32_t num, uint8_t *export_policy, uint32_t src_asn, uint32_t src_next_hop, uint8_t oprt_type, route_t *src_route);
void set_free(set_t **pp_set);
void set_write_elmnts_to_array(uint32_t *p, set_t *p_set);
int update_prefix_sets(set_t **pp_set, route_list_t *p_rl, uint8_t *p_active_parts, uint32_t num);

#endif
