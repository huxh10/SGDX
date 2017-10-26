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
uint8_t *g_call_buff = NULL;
uint32_t g_call_size = 0;
bgp_route_input_dsrlz_msg_t *gp_current_input_msg = NULL;

static sgx_enclave_id_t load_enclave()
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
        fprintf(stdout, "enclave - id %lu [%s]\n", enclave_id, __FUNCTION__);
        return enclave_id;
    }
}

void init_w_sgx(as_cfg_t *p_as_cfg, int verbose)
{
    uint32_t ret_status, call_status, i;
    g_verbose = verbose;

    g_enclave_id = load_enclave();

    // as map
    call_status = enclave_ecall_load_asmap(g_enclave_id, &ret_status, p_as_cfg->as_size, (void *) p_as_cfg->as_id_2_n, p_as_cfg->as_size * sizeof *p_as_cfg->as_id_2_n);
    if (ret_status == SUCCESS) {
        fprintf(stdout, "load as id map done [%s]\n", __FUNCTION__);
    } else {
        fprintf(stderr, "enclave_load_asmap failed, errno:%u [%s]\n", ret_status, __FUNCTION__);
    }
    SAFE_FREE(p_as_cfg->as_id_2_n);

    // as_policies
    for (i = 0; i < p_as_cfg->as_size; i++) {
        call_status = enclave_ecall_load_as_policies(g_enclave_id, &ret_status, i, (void *) p_as_cfg->as_policies[i].import_policy, p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].import_policy, (void *) p_as_cfg->as_policies[i].export_policy, p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].export_policy);
        if (ret_status == SUCCESS) {
            //fprintf(stderr, "enclave_load_as_policies as_id:%u done [%s]\n", i, __FUNCTION__);
        } else {
            fprintf(stderr, "enclave_load_as_policies failed, as_id:%u, errno:%u [%s]\n", i, ret_status, __FUNCTION__);
            exit(-1);
        }
        SAFE_FREE(p_as_cfg->as_policies[i].import_policy);
        SAFE_FREE(p_as_cfg->as_policies[i].export_policy);
    }
    fprintf(stdout, "load as policies done [%s]\n", __FUNCTION__);
}

void process_bgp_route_w_sgx(const bgp_route_input_dsrlz_msg_t *p_bgp_dsrlz_msg)
{
    uint32_t call_status, ret_status;
    gp_current_input_msg = p_bgp_dsrlz_msg;
    call_status = enclave_ecall_filter_route(g_enclave_id, p_bgp_dsrlz_msg->asn);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_process_non_transit_route, errno: %d [%s]\n", ret_status, __FUNCTION__);
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

uint32_t ocall_send_bgp_ret(uint32_t *msg, size_t msg_size)
{
    handle_bgp_route(gp_current_input_msg, msg, msg_size);

    return SUCCESS;
}
