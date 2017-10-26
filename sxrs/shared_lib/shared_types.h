#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <stdint.h>
#include "bgp.h"
#include "uthash.h"

#define CALL_BUFF_MAX 100000

// next hop policy type
//
// import_policy[as_size] for route announcement
//      import_policy[i] is true means accepting routes from as i
//
// export_policy[as_size] for route announcement
//      export_policy[i] is true means sending routes to as i
typedef struct {
    uint8_t *import_policy;
    uint8_t *export_policy;
} as_policy_t;

typedef struct {
    uint32_t as_n;      // key
    uint32_t as_id;     // value
    UT_hash_handle hh;
} asn_map_t;

// all runtime related states
//
// [del] sdn_orgnl_reach[as_size * as_size] for SDX encoding
//      sdn_orngl_reach[as_size * i + j] is true means as j is a destination in i's SDN policies
//
// [del] rib_map_t *ribs[as_size] is a list of rib pointers
typedef struct {
    uint32_t as_size;
    uint32_t *as_id_2_n;
    asn_map_t *as_n_2_id;
    as_policy_t *as_policies;
} rt_state_t;

#endif
