#ifndef __MSG_HANDLER_H__
#define __MSG_HANDLER_H__

#include "bgp.h"

void handle_resp_route(resp_dec_msg_t *p_resp_dec_msg);

void handle_bgp_msg(char *msg);

void handle_pctrlr_msg(char *msg, int src_sfd, int *pctrlr_sfds, int as_num);

#endif
