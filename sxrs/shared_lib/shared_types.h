#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <stdint.h>

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

// next hop policy type
// import_policy[total_num] for route selection
//      import_policy[i] means the order of as i route
//      the lower the value is, the higher selection order the as route is
// export_policy[total_num][total_num] for route announcement
//      export_policy[i][j] means sending routes that which next hop is as i to as j
typedef struct {
    uint32_t asn;
    uint32_t total_num;
    uint8_t *import_policy;
    uint8_t *export_policy;
} as_policy_t;

#endif
