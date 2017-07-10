#ifndef __ROUTE_PROCESS_WO_SGX_H__
#define __ROUTE_PROCESS_WO_SGX_H__

#include "shared_types.h"
#include "bgp.h"

void route_process_wo_sgx_init(uint32_t as_num, as_policy_t **pp_as_policies, int verbose);

void route_process_wo_sgx_run(const bgp_dec_msg_t *p_bgp_dec_msg);

void process_sdn_reach_wo_sgx(uint32_t asid, const uint32_t *p_ases, uint32_t as_size, uint8_t oprt_type);

void get_sdn_reach_by_prefix_wo_sgx(uint32_t asid, const char *prefix);

#endif
