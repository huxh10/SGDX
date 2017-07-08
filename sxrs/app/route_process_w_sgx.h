#ifndef __ROUTE_PROCESS_W_SGX_H__
#define __ROUTE_PROCESS_W_SGX_H__

#include "shared_types.h"
#include "bgp.h"

void init_w_sgx(as_cfg_t *p_as_cfg, int verbose);

void process_bgp_route_w_sgx(const bgp_dec_msg_t *p_bgp_dec_msg);

void process_w_sgx_update_active_parts(uint32_t asn, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type);

void process_w_sgx_get_prefix_set(uint32_t asn, const char *prefix);

#endif
