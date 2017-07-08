#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "enclave_t.h"
#include "sgx_trts.h"
#include "shared_types.h"
#include "error_codes.h"
#include "bgp.h"
#include "rs.h"
#include "enclave.h"

rt_state_t *gp_rt_states = NULL;
route_t g_tmp_route;
uint32_t g_tmp_asn, g_tmp_asid;

uint32_t g_num = 0;
as_policy_t *g_p_policies = NULL;
rib_map_t **g_pp_ribs = NULL;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

uint32_t ecall_load_asmap(uint32_t as_size, void *msg, size_t msg_size)
{
    uint32_t i;
    asn_map_t *asmap_entry;

    if (!gp_rt_states) {
        gp_rt_states = malloc(sizeof *gp_rt_states);
        if (!gp_rt_states) {
            printf("malloc error for gp_rt_states [%s]\n", __FUNCTION__);
            return MALLOC_ERROR;
        }
    }

    // copy asid_2_n to enclave
    gp_rt_states->as_size = as_size;
    gp_rt_states->as_id_2_n = malloc(as_size * sizeof *gp_rt_states->as_id_2_n);
    if (!gp_rt_states->as_id_2_n) {
        printf("malloc error for gp_rt_states->as_id_2_n [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(msg_size == as_size * sizeof *gp_rt_states->as_id_2_n);
    memcpy(gp_rt_states->as_id_2_n, msg, msg_size);

    // construct asn_2_id map
    gp_rt_states->as_n_2_id = NULL;
    for (i = 0; i < as_size; i++) {
        asmap_entry = malloc(sizeof *asn_map_t);
        if (!asmap_entry) {
            printf("malloc error for asmap_entry, id:%d [%s]\n", i, __FUNCTION__);
            return MALLOC_ERROR;
        }
        asmap_entry->as_n = gp_rt_states->as_id_2_n[i];
        asmap_entry->as_id = i;
        HASH_ADD_INT(gp_rt_states->as_n_2_id, asmap_entry->as_n, asmap_entry);
    }

    // allocate memory for the rest states
    gp_rt_states->as_policies = malloc(as_size * sizeof *gp_rt_states->as_policies);
    gp_rt_states->sdn_orgnl_reach = malloc(as_size * sizeof *gp_rt_states->sdn_orgnl_reach);
    gp_rt_states->ribs = malloc(as_size * sizeof *gp_rt_states->ribs);
    if (!gp_rt_states->as_policies || !gp_rt_states->sdn_orgnl_reach || !gp_rt_states->ribs) {
        printf("malloc error for gp_rt_states rest states [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    for (i = 0; i < as_size; i++) {
        // set default value false
        gp_rt_states->sdn_orgnl_reach[i] = 0;
    }
}

uint32_t ecall_load_as_policies(uint32_t asid, void *import_msg, size_t import_msg_size, void *export_msg, size_t export_msg_size, void *selection_msg, size_t selection_msg_size)
{
    gp_rt_states->as_policies[asid].import_policy = malloc(gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].import_policy);
    if (!gp_rt_states->as_policies[asid].import_policy) {
        printf("malloc error for gp_rt_states->as_policies[%d].import_policy [%s]\n", asid, __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(import_msg_size == gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].import_policy)
    memcpy(gp_rt_states->as_policies[asid].import_policy, import_msg, import_msg_size);

    gp_rt_states->as_policies[asid].export_policy = malloc(gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].export_policy);
    if (!gp_rt_states->as_policies[asid].export_policy) {
        printf("malloc error for gp_rt_states->as_policies[%d].export_policy [%s]\n", asid, __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(export_msg_size == gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].export_policy)
    memcpy(gp_rt_states->as_policies[asid].export_policy, export_msg, export_msg_size);

    gp_rt_states->as_policies[asid].selection_policy = malloc(gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].selection_policy);
    if (!gp_rt_states->as_policies[asid].selection_policy) {
        printf("malloc error for gp_rt_states->as_policies[%d].selection_policy [%s]\n", asid, __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(selection_msg_size == gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].selection_policy)
    memcpy(gp_rt_states->as_policies[asid].selection_policy, selection_msg, selection_msg_size);

    return SGX_SUCCESS;
}

uint32_t ecall_load_rib_file_line(uint32_t asid, char *line)
{
    return process_rib_file_line(asid, line, &g_tmp_asn, &g_tmp_asid, &g_tmp_route, gp_rt_states);
}

uint32_t ecall_process_non_transit_route(void *msg, size_t msg_size)
{
    bgp_route_output_dsrlz_msg_t *p_bgp_route_output_dsrlz_msgs = NULL;
    sdn_reach_output_dsrlz_msg_t *p_sdn_reach_output_dsrlz_msgs = NULL;
    uint8_t *ret_msg = NULL;
    size_t i, bgp_output_msg_num = 0, sdn_output_msg_num = 0, ret_msg_size = 0;
    uint32_t call_status, ret_status;

    bgp_route_input_srlz_msg_t *p_bgp_route_input_srlz_msg = msg;
    assert(p_bgp_route_input_srlz_msg->msg_size == msg_size);
    // get original route from input message
    bgp_route_input_dsrlz_msg_t bgp_route_input_dsrlz_msg;
    bgp_route_input_dsrlz_msg.asn = p_bgp_route_input_srlz_msg->asn;
    bgp_route_input_dsrlz_msg.asid = p_bgp_route_input_srlz_msg->asid;
    bgp_route_input_dsrlz_msg.oprt_type = p_bgp_route_input_srlz_msg->oprt_type;
    bgp_route_input_dsrlz_msg.p_route = NULL;
    parse_route_from_stream(&bgp_route_input_dsrlz_msg.p_route, p_bgp_route_input_srlz_msg->route);
    assert(bgp_route_input_dsrlz_msg.p_route);
    assert(bgp_route_input_dsrlz_msg.p_route->as_path.asns);

    if ((ret_status = process_non_transit_route(&bgp_route_input_dsrlz_msg, gp_rt_states, &p_bgp_route_output_dsrlz_msgs, &bgp_output_msg_num, &p_sdn_reach_output_dsrlz_msgs, &sdn_output_msg_num)) != SUCCESS) {
        free_route_ptr(&bgp_route_input_dsrlz_msg.p_route);
        return ret_status;
    }

    // return messages
    if (!bgp_output_msg_num && !sdn_output_msg_num) return SUCCESS;
    if ((ret_msg_size = write_bgp_ret_to_stream(&ret_msg, p_bgp_route_output_dsrlz_msgs, bgp_output_msg_num, p_sdn_reach_output_dsrlz_msgs, sdn_output_msg_num)) == -1) return MALLOC_ERROR;
    call_status = ocall_send_bgp_ret(&ret_status, (void *) ret_msg, ret_msg_size);
    SAFE_FREE(ret_msg);
    for (i = 0; i < bgp_output_msg_num; i++) {
        free_bgp_route_output_dsrlz_msg(&p_bgp_route_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_bgp_route_output_dsrlz_msgs);
    for (i = 0; i < sdn_output_msg_num; i++) {
        free_sdn_reach_output_dsrlz_msg(&p_sdn_reach_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_sdn_reach_output_dsrlz_msgs);
    free_route_ptr(&bgp_route_input_dsrlz_msg.p_route);
    if (call_status == SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }
}

uint32_t ecall_update_active_parts(uint32_t asn, const uint32_t *p_parts, size_t part_num, uint8_t oprt_type)
{
    return update_active_parts(g_p_policies[asn].active_parts, p_parts, part_num, oprt_type);
}

uint32_t ecall_get_prefix_set(uint32_t asn, const char *prefix)
{
    uint32_t call_status, ret_status;
    uint32_t *p_resp_set = NULL;
    uint32_t resp_set_size = 0;

    get_prefix_set(prefix, g_p_policies[asn].active_parts, g_num, g_pp_ribs[asn], &p_resp_set, &resp_set_size);
    call_status = ocall_send_sdn_ret(&ret_status, p_resp_set, (size_t) resp_set_size, asn, prefix);
    SAFE_FREE(p_resp_set);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SGX_SUCCESS) return ret_status;
    } else {
        return call_status;
    }
}

uint32_t ecall_get_rs_ribs_num()
{
    return get_rs_ribs_num(g_pp_ribs, g_num);
}

uint32_t ecall_print_rs_ribs()
{
    return print_rs_ribs(g_pp_ribs, g_num);
}
