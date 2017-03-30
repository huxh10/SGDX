#include <stdio.h>
#include "app_types.h"
#include "shared_types.h"
#include "msg_handler.h"
#include "error_codes.h"
#include "bgp.h"
#include "rs.h"
#include "route_process_wo_sgx.h"

uint32_t g_num = 0;
as_policy_t *g_p_policies = NULL;
rib_map_t **g_pp_ribs = NULL;

void route_process_wo_sgx_init(uint32_t as_num, as_policy_t **pp_as_policies)
{
    uint32_t i = 0;

    g_num = as_num;
    g_p_policies = malloc(as_num * sizeof *g_p_policies);
    g_pp_ribs = malloc(as_num * sizeof *g_pp_ribs);
    for (i = 0; i < as_num; i++) {
        g_pp_ribs[i] = NULL;
        g_p_policies[i].asn = i;
        g_p_policies[i].total_num = as_num;
        g_p_policies[i].active_parts = malloc(as_num * sizeof *g_p_policies[i].active_parts);
        memset(g_p_policies[i].active_parts, 0, as_num * sizeof(*g_p_policies[i].active_parts));
        g_p_policies[i].import_policy = malloc(as_num * sizeof *g_p_policies[i].import_policy);
        memcpy(g_p_policies[i].import_policy, (*pp_as_policies)[i].import_policy, as_num * sizeof (*pp_as_policies)[i].import_policy);
        g_p_policies[i].export_policy = malloc(as_num * as_num * sizeof *g_p_policies[i].export_policy);
        memcpy(g_p_policies[i].export_policy, (*pp_as_policies)[i].export_policy, as_num * as_num * sizeof (*pp_as_policies)[i].export_policy);
        SAFE_FREE((*pp_as_policies)[i].import_policy);
        SAFE_FREE((*pp_as_policies)[i].export_policy);
    }
    SAFE_FREE(*pp_as_policies);
}

void route_process_wo_sgx_run(bgp_dec_msg_t *p_bgp_dec_msg)
{
    uint32_t i = 0;
    resp_dec_msg_t *p_resp_dec_msgs = NULL;
    size_t resp_msg_num = 0;

    compute_route_by_msg_queue(p_bgp_dec_msg, g_p_policies, g_pp_ribs, g_num, &p_resp_dec_msgs, &resp_msg_num);

    if (!resp_msg_num) return;

    for (i = 0; i < resp_msg_num; i++) {
        handle_resp_route(&p_resp_dec_msgs[i]);
        free_resp_dec_msg(&p_resp_dec_msgs[i]);
    }
    SAFE_FREE(p_resp_dec_msgs);

    return;
}

void process_wo_sgx_update_active_parts(uint32_t asn, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type)
{
    update_active_parts(g_p_policies[asn].active_parts, p_parts, part_num, oprt_type);
}

void process_wo_sgx_get_prefix_set(uint32_t asn, const char *prefix)
{
    uint32_t *p_resp_set = NULL;
    uint32_t resp_set_size = 0;

    get_prefix_set(prefix, g_p_policies[asn].active_parts, g_num, g_pp_ribs[asn], &p_resp_set, &resp_set_size);
    handle_resp_set(asn, prefix, p_resp_set, resp_set_size);
    SAFE_FREE(p_resp_set);
}
