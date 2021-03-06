#ifndef __MSG_HANDLER_H__
#define __MSG_HANDLER_H__

#include "bgp.h"
#include "app_types.h"
#include "epoll_utils.h"

void create_start_signal();

void msg_handler_init(as_cfg_t *p_as_cfg);

void handle_sdn_reach(uint32_t asn, const char *prefix, const uint32_t *p_sdn_reach, uint32_t reach_size);

void handle_bgp_route_for_pctrl(bgp_route_output_dsrlz_msg_t *p_bgp_msg);

void handle_bgp_route(bgp_route_output_dsrlz_msg_t *p_bgp_msg);

int handle_exabgp_msg(char *msg);

void handle_pctrlr_msg(char *msg, uint32_t *p_con_id, epoll_event_handler_t *h, epoll_event_handler_t **pp_ehs);

#endif
