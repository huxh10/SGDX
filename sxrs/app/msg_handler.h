#ifndef __MSG_HANDLER_H__
#define __MSG_HANDLER_H__

#include "bgp.h"
#include "app_types.h"
#include "epoll_utils.h"

void create_start_signal();

void msg_handler_init(as_cfg_t *p_as_cfg);

void handle_bgp_route(bgp_route_input_dsrlz_msg_t *p_bgp_msg, uint32_t *p_bgp_output_asids, size_t bgp_output_as_num);

int handle_exabgp_msg(char *msg);

#endif
