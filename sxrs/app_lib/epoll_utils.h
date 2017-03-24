#ifndef _EPOLL_UTILS_H_
#define _EPOLL_UTILS_H_

#include <stdint.h>

typedef struct epoll_event_handler epoll_event_handler_t;

struct epoll_event_handler {
    int efd;
    int fd;
    void (*handle)(epoll_event_handler_t *, uint32_t);
    void *closure;
};

int epoll_init();
void epoll_ctl_handler(epoll_event_handler_t *h, uint32_t ctl_mask, uint32_t e_mask);
void epoll_run(int efd);

#endif
