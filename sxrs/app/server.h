#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdint.h>
#include "app_types.h"

void server_init(int efd, int as_num, net_conf_t *p_ncf);

void send_msg_to_pctrlr(const char *msg, uint32_t asn);

void send_msg_to_as(const char *msg);

#endif
