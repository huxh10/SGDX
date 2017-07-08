#ifndef _BGP_H_
#define _BGP_H_

#include <stdint.h>
#include "uthash.h"

#define ROUTE_FIELD             8
#define ROUTE_DELIMITER_CHAR    ','
#define ROUTE_DELIMITER_STR     ","
#define AS_PATH_DELIMITER_CHAR  ' '
#define AS_PATH_DELIMITER_STR   " "

// oprt_type
#define ANNOUNCE                1
#define WITHDRAW                2

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

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
    uint32_t id;
    set_node_t *prev;
    set_node_t *next;
};

typedef struct {
    int size;
    set_node_t *head;
} set_t;

// rib type
typedef struct _rib_map rib_map_t;

struct _rib_map {
    char *key;
    set_t *augmented_reach;  // augmented reachability for SDN policies
    route_list_t *rl;
    UT_hash_handle hh;
};

typedef struct {
    uint32_t msg_size;
    uint32_t asn;
    uint32_t asid;
    uint8_t oprt_type;
    uint8_t route[];
} bgp_route_input_srlz_msg_t;

typedef struct {
    uint32_t asn;
    uint32_t asid;
    uint8_t oprt_type;
    route_t *p_route;
} bgp_route_input_dsrlz_msg_t;

typedef struct {
    uint32_t asid;
    uint8_t oprt_type;
    char *prefix;
    char *next_hop;
    as_path_t as_path;
} bgp_route_output_dsrlz_msg_t;

typedef struct {
    uint32_t asid;
    char *prefix;
    uint32_t reach_size;
    uint32_t *reachability;
} sdn_reach_output_dsrlz_msg_t;


char *my_strdup(const char *s);
void free_route_ptr(route_t **pp_route);
void reset_route(route_t *p_route);
void free_bgp_route_output_dsrlz_msg(bgp_route_output_dsrlz_msg_t *p_msg);
void free_sdn_reach_output_dsrlz_msg(sdn_reach_output_dsrlz_msg_t *p_msg);
void print_route(route_t *p_route);
void parse_route_from_file(route_t **pp_route, char *p_s_route);
int parse_route_from_stream(route_t **pp_route, const uint8_t *p_s_route);
void route_cpy(route_t **dst_route, uint32_t *src_asn, const route_t *src_route);
int get_route_size(route_t *r);
int write_route_to_stream(uint8_t **pp_msg, route_t *input);
int write_route_to_existed_stream(uint8_t *route, route_t *input);
int parse_bgp_ret_from_stream(bgp_route_output_dsrlz_msg_t **pp_bgp_msgs, size_t *p_bgp_msg_num, sdn_reach_output_dsrlz_msg_t **pp_sdn_msgs, size_t *p_sdn_msg_num, uint8_t *p_msg);
int write_bgp_ret_to_stream(uint8_t **pp_msg, bgp_route_output_dsrlz_msg_t *p_bgp_msgs, size_t bgp_msg_num, sdn_reach_output_dsrlz_msg_t *p_sdn_msgs, size_t sdn_msg_num);
route_node_t* rl_get_selected_route_node(route_list_t *p_rl);
int rl_add_route(route_list_t **pp_rl, uint32_t src_asn, uint32_t src_asid, route_t *src_route, uint8_t *selection_policy);
int rl_del_route(route_list_t **pp_rl, uint32_t src_asn, route_t *src_route, uint8_t *selection_policy);
void set_free(set_t **pp_set);
void set_write_elmnts_to_array(uint32_t *p, set_t *p_set);
int update_augmented_reach(set_t **pp_set, route_list_t *p_rl, uint8_t *p_sdn_reach);

#endif
