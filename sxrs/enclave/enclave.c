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
    uint32_t ret_status;
    ret_status = load_asmap(&gp_rt_states, as_size, (uint32_t *) msg);
    assert(msg_size == as_size * sizeof *gp_rt_states->as_id_2_n);
    return ret_status;
}

uint32_t ecall_load_as_policies(uint32_t asid, void *import_msg, size_t import_msg_size, void *export_msg, size_t export_msg_size)
{
    gp_rt_states->as_policies[asid].import_policy = malloc(gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].import_policy);
    if (!gp_rt_states->as_policies[asid].import_policy) {
        printf("malloc error for gp_rt_states->as_policies[%d].import_policy [%s]\n", asid, __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(import_msg_size == gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].import_policy);
    memcpy(gp_rt_states->as_policies[asid].import_policy, import_msg, import_msg_size);

    gp_rt_states->as_policies[asid].export_policy = malloc(gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].export_policy);
    if (!gp_rt_states->as_policies[asid].export_policy) {
        printf("malloc error for gp_rt_states->as_policies[%d].export_policy [%s]\n", asid, __FUNCTION__);
        return MALLOC_ERROR;
    }
    assert(export_msg_size == gp_rt_states->as_size * sizeof *gp_rt_states->as_policies[asid].export_policy);
    memcpy(gp_rt_states->as_policies[asid].export_policy, export_msg, export_msg_size);

    return SGX_SUCCESS;
}

uint32_t ecall_filter_route(uint32_t asn)
{
    uint32_t *p_bgp_output_asids = NULL;
    size_t bgp_output_as_num = 0;
    uint32_t call_status, ret_status;

    if ((ret_status = filter_route(gp_rt_states, &p_bgp_output_asids, &bgp_output_as_num)) != SUCCESS) {
        return ret_status;
    }

    // return messages
    if (!bgp_output_as_num) return SUCCESS;
    call_status = ocall_send_bgp_ret(&ret_status, p_bgp_output_asids, bgp_output_as_num);
    SAFE_FREE(p_bgp_output_asids);
    if (call_status == SUCCESS && ret_status != SUCCESS) return ret_status;
    return call_status;
}
