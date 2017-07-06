#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <stdint.h>
#include "bgp.h"
#include "uthash.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

// next hop policy type
//
// active_parts[as_size] for SDX encoding
//      active_parts[i] is true means as i is a destination in the SDN policy
//
// import_policy[as_size] for route announcement
//      import_policy[i] is true means accepting routes from as i
//
// export_policy[as_size] for route announcement
//      export_policy[i] is true means sending routes to as i
//
// selection_policy[as_size] for route selection
//      selection_policy[i] represents the priority of as i route
//      the lower the value is, the higher selection order the as route is
typedef struct {
    uint8_t *active_parts;
    uint8_t *import_policy;
    uint8_t *export_policy;
    uint32_t *selection_policy;
} as_policy_t;

typedef struct {
    uint32_t as_n;      // key
    uint32_t as_id;     // value
    UT_hash_handle hh;
} asn_map_t;

typedef struct {
    uint32_t as_size;
    uint32_t *as_id_2_n;
    asn_map_t *as_n_2_id;
    as_policy_t *as_policies;
    rib_map_t **loaded_ribs;
} as_cfg_t;

#endif
