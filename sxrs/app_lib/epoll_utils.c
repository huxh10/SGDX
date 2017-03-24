#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include "epoll_utils.h"

int epoll_init()
{
    int efd;

    efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create1");
        return efd;
    }

    return efd;
}

void epoll_ctl_handler(epoll_event_handler_t *h, uint32_t ctl_mask, uint32_t e_mask)
{
    int ret;
    struct epoll_event event;

    memset(&event, 0, sizeof(event));
    event.data.ptr = h;
    event.events = e_mask;

    ret = epoll_ctl(h->efd, ctl_mask, h->fd, &event);
    if (ret == -1) {
        perror("epoll_ctl error");
        return;
    }
}

void epoll_run(int efd)
{
    struct epoll_event event;
    epoll_event_handler_t *handler;

    while (1) {
        epoll_wait(efd, &event, 1, -1);
        handler = event.data.ptr;
        handler->handle(handler, event.events);
    }
}
