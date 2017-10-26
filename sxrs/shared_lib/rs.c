#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"

uint32_t load_asmap(rt_state_t **pp_rt_states, uint32_t as_size, uint32_t *as_id_2_n)
{
    uint32_t i;
    asn_map_t *asmap_entry;

    if (!pp_rt_states) return INPUT_NULL_POINTER;

    if (!*pp_rt_states) {
        *pp_rt_states = malloc(sizeof **pp_rt_states);
        if (!*pp_rt_states) {
            printf("malloc error for *pp_rt_states [%s]\n", __FUNCTION__);
            return MALLOC_ERROR;
        }
    }

    // copy as_id_2_n
    (*pp_rt_states)->as_size = as_size;
    (*pp_rt_states)->as_id_2_n = malloc(as_size * sizeof *(*pp_rt_states)->as_id_2_n);
    if (!(*pp_rt_states)->as_id_2_n) {
        printf("malloc error for (*pp_rt_states)->as_id_2_n [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    memcpy((*pp_rt_states)->as_id_2_n, as_id_2_n, as_size * sizeof *as_id_2_n);

    // construct asn_2_id map
    (*pp_rt_states)->as_n_2_id = NULL;
    for (i = 0; i < as_size; i++) {
        asmap_entry = malloc(sizeof *asmap_entry);
        if (!asmap_entry) {
            printf("malloc error for asmap_entry, id:%d [%s]\n", i, __FUNCTION__);
            return MALLOC_ERROR;
        }
        asmap_entry->as_n = (*pp_rt_states)->as_id_2_n[i];
        asmap_entry->as_id = i;
        HASH_ADD_INT((*pp_rt_states)->as_n_2_id, as_n, asmap_entry);
    }

    // allocate memory for the rest states
    (*pp_rt_states)->as_policies = malloc(as_size * sizeof *(*pp_rt_states)->as_policies);
    if (!(*pp_rt_states)->as_policies) {
        printf("malloc error for (*pp_rt_states) rest states [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    return SUCCESS;
}

uint32_t filter_route(rt_state_t *p_rt_states, uint32_t asn, uint32_t **pp_bgp_output_asids, size_t *p_bgp_output_as_num)
{
    int i, j;
    uint32_t asid;
    asn_map_t *asmap_entry;
    uint8_t valid_output_ases[p_rt_states->as_size];

    *p_bgp_output_as_num = 0;

    // get original route from input message
    HASH_FIND_INT(gp_rt_states->as_n_2_id, asn, asmap_entry);
    asid = asmap_entry->as_id;

    for (i = 0; i < p_rt_states->as_size; i++) {
        valid_output_ases[i] = 0;
        // execute filter policies
        if (!p_rt_states->as_policies[asid].export_policy[i]) continue;
        if (!p_rt_states->as_policies[i].import_policy[asid]) continue;
        valid_output_ases[i] = 1;
        (*p_bgp_output_as_num)++;
    }

    // return bgp output ases
    if (*p_bgp_output_as_num == 0) return SUCCESS;
    *pp_bgp_output_asids = malloc(*p_bgp_output_as_num * sizeof **pp_bgp_output_asids);
    if (!*pp_bgp_output_asids) {
        printf("malloc error for pp_bgp_output_asids [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    j = 0;
    for (i = 0; i < p_rt_states->as_size; i++) {
        if (!valid_output_ases[i]) continue;
        (*pp_bgp_output_asids)[j] = i;
        j++;
    }
    assert(j == *p_bgp_output_as_num);

    return SUCCESS;
}
