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

void init_w_sgx(as_cfg_t *p_as_cfg, int verbose)
{
    uint32_t ret_status, call_status, i;
    g_verbose = verbose;

    g_enclave_id = load_enclave();

    // as map
    call_status = enclave_ecall_load_asmap(g_enclave_id, &ret_status, p_as_cfg->as_size, (void *) p_as_cfg->as_id_2_n, p_as_cfg->as_size * sizeof *p_as_cfg->as_id_2_n);
    if (ret_status == SUCCESS) {
        //fprintf(stderr, "enclave_load_asmap done [%s]\n", __FUNCTION__);
    } else {
        //fprintf(stderr, "enclave_load_asmap failed, errno:%u [%s]\n", ret_status, __FUNCTION__);
    }
    SAFE_FREE(p_as_cfg->as_id_2_n);

    // as_policies
    for (i = 0; i < p_as_cfg->as_size; i++) {
        call_status = enclave_ecall_load_as_policies(g_enclave_id, &ret_status, i, (void *) p_as_cfg->as_policies[i].import_policy, p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].import_policy, (void *) p_as_cfg->as_policies[i].export_policy, p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].export_policy, (void *) p_as_cfg->as_policies[i].selection_policy, p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].selection_policy);
        if (ret_status == SUCCESS) {
            //fprintf(stderr, "enclave_load_as_policies asn:%u done [%s]\n", i, __FUNCTION__);
        } else {
            //fprintf(stderr, "enclave_load_as_policies failed, asn:%u, errno:%u [%s]\n", i, ret_status, __FUNCTION__);
            exit(-1);
        }
        SAFE_FREE(p_as_cfg->as_policies[i].import_policy);
        SAFE_FREE(p_as_cfg->as_policies[i].export_policy);
        SAFE_FREE(p_as_cfg->as_policies[i].selection_policy);
    }

    // ribs
    if (!p_as_cfg->rib_file_dir) return;
    int dir_len = strlen(p_as_cfg.rib_file_dir);
    char rib_file[dir_len + 9] = {0};   // 9 is for rib name (8), such as rib_1000, and '\0' (1)
    memcpy(rib_file, p_as_cfg.rib_file_dir, dir_len);
    char *line = NULL;                  // buffer address
    size_t len = 0;                     // allocated buffer size
    for (i = 0; i < p_as_cfg->as_size; i++) {
        sprinf(rib_file + dir_len, "rib_%d", i);
        if ((fp = fopen(rib_file, "r")) == NULL) {
            fprintf(stderr, "can not open file: %s [%s]\n", rib_file, __FUNCTION__);
            exit(-1);
        }
        while (getline(&line, &len, fp) != -1) {
            enclave_ecall_load_rib_file_line(g_enclave_id, &ret_status, i, line);
        }
        fclose(fp);
    }
    SAFE_FREE(line);
}

void process_bgp_route_w_sgx(const bgp_route_input_dsrlz_msg_t *p_bgp_dsrlz_msg)
{
    uint32_t call_status, ret_status;
    int route_size = get_route_size(p_bgp_dsrlz_msg->p_route);
    int msg_size = sizeof(bgp_enc_msg_t) + route_size;
    bgp_route_input_srlz_msg_t *p_bgp_srlz_msg = malloc(msg_size);
    p_bgp_srlz_msg->msg_size = msg_size;
    p_bgp_srlz_msg->asn = p_bgp_dsrlz_msg->asn;
    p_bgp_srlz_msg->oprt_type = p_bgp_dsrlz_msg->oprt_type;
    write_route_to_existed_stream(p_bgp_srlz_msg->route, p_bgp_dsrlz_msg->p_route);

    call_status = enclave_ecall_process_non_transit_route(g_enclave_id, &ret_status, (void *) p_bgp_srlz_msg, msg_size);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_process_non_transit_route, errno: %d [%s]\n", ret_status, __FUNCTION__);
    }
    SAFE_FREE(p_bgp_srlz_msg);
    if (g_verbose == 4) enclave_ecall_print_rs_ribs(g_enclave_id, &ret_status);
}

void process_sdn_reach_w_sgx(uint32_t asid, const uint32_t *p_reach, uint32_t reach_size, uint8_t oprt_type)
{
    uint32_t call_status, ret_status;

    call_status = enclave_ecall_process_sdn_reach(g_enclave_id, &ret_status, asid, p_reach, (size_t) reach_size, oprt_type);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_process_sdn_reach, errno: %d [%s]\n", ret_status, __FUNCTION__);
    }
}

void get_sdn_reach_by_prefix_w_sgx(uint32_t asid, const char *prefix)
{
    uint32_t call_status, ret_status;

    call_status = enclave_ecall_get_sdn_reach_by_prefix(g_enclave_id, &ret_status, asid, prefix);
    if (ret_status != SUCCESS) {
        fprintf(stderr, "enclave_ecall_get_sdn_reach_by_prefix, errno: %d [%s]\n", ret_status, __FUNCTION__);
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

uint32_t ocall_send_bgp_ret(void *msg, size_t msg_size)
{
    uint32_t i = 0;
    bgp_route_output_dsrlz_msg_t *p_bgp_route_output_dsrlz_msgs = NULL;
    sdn_reach_output_dsrlz_msg_t *p_sdn_reach_output_dsrlz_msgs = NULL;
    size_t bgp_msg_num = 0, sdn_msg_num = 0;

    assert(parse_bgp_ret_from_stream(&p_bgp_route_output_dsrlz_msgs, &bgp_msg_num, &p_sdn_reach_output_dsrlz_msgs, &sdn_msg_num, (uint8_t *) msg) == msg_size);

    for (i = 0; i < bgp_msg_num; i++) {
        handle_bgp_route(&p_bgp_route_output_dsrlz_msgs[i]);
        free_bgp_route_output_dsrlz_msg(&p_bgp_route_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_bgp_route_output_dsrlz_msgs);
    for (i = 0; i < sdn_msg_num; i++) {
        handle_sdn_reach(p_sdn_reach_output_dsrlz_msgs[i].asid, p_sdn_reach_output_dsrlz_msgs[i].prefix, p_sdn_reach_output_dsrlz_msgs[i].reachability, p_sdn_reach_output_dsrlz_msgs[i].reach_size);
        free_sdn_reach_output_dsrlz_msg(&p_sdn_reach_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_sdn_reach_output_dsrlz_msgs);

    return SUCCESS;
}

uint32_t ocall_send_sdn_ret(uint32_t *p_sdn_reach, size_t reach_size, uint32_t asid, const char *prefix)
{
    handle_sdn_reach(asid, prefix, p_sdn_reach, reach_size);
}
