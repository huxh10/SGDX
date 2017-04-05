#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "app_types.h"
#include "shared_types.h"
#include "msg_handler.h"
#include "error_codes.h"
#include "bgp.h"
#include "rs.h"
#include "../enclave/enclave_u.h"
#include "route_process_w_sgx.h"

sgx_enclave_id_t g_enclave_id;
int g_verbose = 0;

sgx_enclave_id_t load_enclave()
{
    char enclave_path[] = "libenclave.so";
    int launch_token_updated;
    sgx_launch_token_t launch_token;
    sgx_enclave_id_t enclave_id;
    uint32_t ret;

    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave failed, errno:%d [%s]\n", ret, __FUNCTION__);
        exit(-1);
    } else {
        fprintf(stderr, "enclave - id %lu [%s]\n", enclave_id, __FUNCTION__);
        return enclave_id;
    }
}

void route_process_w_sgx_init(uint32_t as_num, as_policy_t **pp_as_policies, int verbose)
{
    uint32_t ret_status, call_status, i;
    g_verbose = verbose;
    g_enclave_id = load_enclave();
    for (i = 0; i < as_num; i++) {
        call_status = enclave_ecall_load_as_policies(g_enclave_id, &ret_status, i, (void *) (*pp_as_policies)[i].import_policy, as_num * sizeof *(*pp_as_policies)[i].import_policy, (void *) (*pp_as_policies)[i].export_policy, as_num * as_num * sizeof *(*pp_as_policies)[i].export_policy);
        if (ret_status == SUCCESS) {
            //fprintf(stderr, "enclave_load_as_policies asn:%u succeeded [%s]\n", i, __FUNCTION__);
        } else {
            //fprintf(stderr, "enclave_load_as_policies failed, asn:%u, errno:%u [%s]\n", i, ret_status, __FUNCTION__);
            exit(-1);
        }
        SAFE_FREE((*pp_as_policies)[i].import_policy);
        SAFE_FREE((*pp_as_policies)[i].export_policy);
    }
    SAFE_FREE(*pp_as_policies);
}

void route_process_w_sgx_run(const bgp_dec_msg_t *p_bgp_dec_msg)
{
    uint32_t call_status, ret_status;
    int route_size = get_route_size(p_bgp_dec_msg->p_route);
    int msg_size = sizeof(bgp_enc_msg_t) + route_size;
    bgp_enc_msg_t *p_bgp_enc_msg = malloc(msg_size);
    p_bgp_enc_msg->msg_size = msg_size;
    p_bgp_enc_msg->asn = p_bgp_dec_msg->asn;
    p_bgp_enc_msg->oprt_type = p_bgp_dec_msg->oprt_type;
    write_route_to_existed_stream(p_bgp_enc_msg->route, p_bgp_dec_msg->p_route);

    call_status = enclave_ecall_compute_route_by_msg_queue(g_enclave_id, &ret_status, (void *) p_bgp_enc_msg, msg_size);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_compute_route_by_msg_queue, errno: %d [%s]\n", ret_status, __FUNCTION__);
    }
    SAFE_FREE(p_bgp_enc_msg);
    if (g_verbose == 4) enclave_ecall_print_rs_ribs(g_enclave_id, &ret_status);
}

void process_w_sgx_update_active_parts(uint32_t asn, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type)
{
    uint32_t call_status, ret_status;

    call_status = enclave_ecall_update_active_parts(g_enclave_id, &ret_status, asn, p_parts, (size_t) part_num, oprt_type);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_compute_route_by_msg_queue, errno: %d [%s]\n", ret_status, __FUNCTION__);
    }
}

void process_w_sgx_get_prefix_set(uint32_t asn, const char *prefix)
{
    uint32_t call_status, ret_status;

    call_status = enclave_ecall_get_prefix_set(g_enclave_id, &ret_status, asn, prefix);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_compute_route_by_msg_queue, errno: %d [%s]\n", ret_status, __FUNCTION__);
    }
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

uint32_t ocall_send_route(void *msg, size_t msg_size)
{
    uint32_t i = 0;
    resp_dec_msg_t *p_resp_dec_msgs = NULL;
    resp_dec_set_msg_t *p_resp_dec_set_msgs = NULL;
    size_t resp_msg_num = 0, resp_set_msg_num = 0;

    assert(parse_resp_from_stream(&p_resp_dec_msgs, &resp_msg_num, &p_resp_dec_set_msgs, &resp_set_msg_num, (uint8_t *) msg) == msg_size);

    for (i = 0; i < resp_msg_num; i++) {
        handle_resp_route(&p_resp_dec_msgs[i]);
        free_resp_dec_msg(&p_resp_dec_msgs[i]);
    }
    SAFE_FREE(p_resp_dec_msgs);
    for (i = 0; i < resp_set_msg_num; i++) {
        handle_resp_set(p_resp_dec_set_msgs[i].asn, p_resp_dec_set_msgs[i].prefix, p_resp_dec_set_msgs[i].set, p_resp_dec_set_msgs[i].set_size);
        free_resp_dec_set_msg(&p_resp_dec_set_msgs[i]);
    }
    SAFE_FREE(p_resp_dec_set_msgs);

    return SUCCESS;
}

uint32_t ocall_send_prefix_set(uint32_t *p_resp_set, size_t resp_set_size, uint32_t asn, const char *prefix)
{
    handle_resp_set(asn, prefix, p_resp_set, resp_set_size);
}
