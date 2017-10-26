#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdint.h>
#include "app_types.h"

void server_init(int efd, net_conf_t *p_ncf, int as_size);

void send_msg_to_as(const char *msg);

#endif
