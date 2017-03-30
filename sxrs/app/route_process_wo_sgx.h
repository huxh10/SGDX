#ifndef __ROUTE_PROCESS_WO_SGX_H__
#define __ROUTE_PROCESS_WO_SGX_H__

#include "shared_types.h"
#include "bgp.h"

void route_process_wo_sgx_init(uint32_t as_num, as_policy_t **pp_as_policies);

void route_process_wo_sgx_run(bgp_dec_msg_t *p_bgp_dec_msg);

void process_wo_sgx_update_active_parts(uint32_t asn, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type);

void process_wo_sgx_get_prefix_set(uint32_t asn, const char *prefix);

#endif
