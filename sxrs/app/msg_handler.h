#ifndef __MSG_HANDLER_H__
#define __MSG_HANDLER_H__

#include "bgp.h"

void handle_sdn_reach(uint32_t asn, const char *prefix, const uint32_t *p_resp_set, uint32_t resp_set_size);

void handle_bgp_route(bgp_route_output_dsrlz_msg_t *p_bgp_msg);

void handle_bgp_msg(char *msg);

void handle_pctrlr_msg(char *msg, int src_sfd, uint32_t *p_src_id, int *pctrlr_bgp_sfds, int *pctrlr_ss_sfds, int as_num);

#endif
