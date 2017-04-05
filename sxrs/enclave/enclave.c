#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "enclave_t.h"
#include "sgx_trts.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"
#include "enclave.h"

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

uint32_t ecall_load_as_policies(uint32_t asn, void *import_msg, size_t import_msg_size, void *export_msg, size_t export_msg_size)
{
    uint32_t i = 0, total_num = import_msg_size; // depends on import_policy type
    if (g_p_policies == NULL) {
        g_num = total_num;
        g_p_policies = malloc(total_num * sizeof *g_p_policies);
        g_pp_ribs = malloc(total_num * sizeof *g_pp_ribs);
        if (!g_p_policies || !g_pp_ribs) {
            printf("malloc err: out of memory [%s]\n", __FUNCTION__);
            return 10;
        }
        for (i = 0; i < total_num; i++) {
            g_pp_ribs[i] = NULL;
        }
    }
    g_p_policies[asn].asn = asn;
    g_p_policies[asn].total_num = total_num;
    g_p_policies[asn].active_parts = malloc(total_num * sizeof *g_p_policies[asn].active_parts);
    if (!g_p_policies[asn].active_parts) {
        printf("malloc err: out of memory [%s]\n", __FUNCTION__);
        return 10;
    }
    memset(g_p_policies[asn].active_parts, 0, total_num * sizeof *g_p_policies[asn].active_parts);
    g_p_policies[asn].import_policy = malloc(total_num * sizeof *g_p_policies[asn].import_policy);
    if (!g_p_policies[asn].import_policy) {
        printf("malloc err: out of memory [%s]\n", __FUNCTION__);
        return 10;
    }
    memcpy(g_p_policies[asn].import_policy, import_msg, import_msg_size);
    g_p_policies[asn].export_policy = malloc(total_num * total_num * sizeof *g_p_policies[asn].export_policy);
    if (!g_p_policies[asn].export_policy) {
        printf("malloc err: out of memory [%s]\n", __FUNCTION__);
        return 10;
    }
    memcpy(g_p_policies[asn].export_policy, export_msg, export_msg_size);
    return SGX_SUCCESS;
}

uint32_t ecall_compute_route_by_msg_queue(void *msg, size_t msg_size)
{
    resp_dec_msg_t *p_resp_dec_msgs = NULL;
    size_t i, resp_msg_num = 0, resp_msg_size = 0;
    resp_dec_set_msg_t *p_resp_dec_set_msgs = NULL;
    size_t resp_set_msg_num = 0;
    uint8_t *resp_msg = NULL;
    uint32_t call_status, ret_status;

    bgp_enc_msg_t *p_bgp_enc_msg = msg;
    assert(p_bgp_enc_msg->msg_size == msg_size);
    // get original route from the message
    bgp_dec_msg_t bgp_dec_msg;
    bgp_dec_msg.asn = p_bgp_enc_msg->asn;
    bgp_dec_msg.oprt_type = p_bgp_enc_msg->oprt_type;
    bgp_dec_msg.p_route = NULL;
    parse_route_from_stream(&bgp_dec_msg.p_route, p_bgp_enc_msg->route);
    assert(bgp_dec_msg.p_route);
    assert(bgp_dec_msg.p_route->as_path.asns);

    compute_route_by_msg_queue(&bgp_dec_msg, g_p_policies, g_pp_ribs, g_num, &p_resp_dec_msgs, &resp_msg_num, &p_resp_dec_set_msgs, &resp_set_msg_num);

    // process response messages
    if (!resp_msg_num && !resp_set_msg_num) {
        return SGX_SUCCESS;
    }
    resp_msg_size = write_resp_to_stream(&resp_msg, p_resp_dec_msgs, resp_msg_num, p_resp_dec_set_msgs, resp_set_msg_num);
    call_status = ocall_send_route(&ret_status, (void *) resp_msg, resp_msg_size);
    SAFE_FREE(resp_msg);
    for (i = 0; i < resp_msg_num; i++) {
        free_resp_dec_msg(&p_resp_dec_msgs[i]);
    }
    SAFE_FREE(p_resp_dec_msgs);
    for (i = 0; i < resp_set_msg_num; i++) {
        free_resp_dec_set_msg(&p_resp_dec_set_msgs[i]);
    }
    SAFE_FREE(p_resp_dec_set_msgs);
    free_route_ptr(&bgp_dec_msg.p_route);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SGX_SUCCESS) return ret_status;
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
    call_status = ocall_send_prefix_set(&ret_status, p_resp_set, (size_t) resp_set_size, asn, prefix);
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
