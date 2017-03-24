#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <assert.h>
#include <errno.h>
#include "epoll_utils.h"
#include "socket_utils.h"
#include "msg_buffer.h"
#include "app_types.h"
#include "msg_handler.h"
#include "server.h"

typedef struct {
    uint32_t id;
    ds_t *p_ds;
} server_read_closure_t;

int g_bgp_serv_sfd, g_bgp_clnt_sfd;
int *g_pctrlr_sfds;
int g_as_num;

static inline void send_msg(const char *msg, uint32_t sfd)
{
    int i, bytes, diff, offset = 0, msg_size = strlen(msg);

    while (msg_size != offset) {
        diff = msg_size - offset;
        bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
        if (write(sfd, msg + offset, bytes) == -1) {
            // fprintf(stdout, "\n[app] write mqueue failed dst_id:%d, err: %s [%s]\n", bgp_msg->dst_id, strerror(errno), __FUNCTION__);
        } else {
            //// fprintf(stdout, "\n[app] write mqueue %d bytes successfully, to agent %d [%s]\n", bytes, bgp_msg->dst_id, __FUNCTION__);
            offset += bytes;
        }
    }
}

void send_msg_to_pctrlr(const char *msg, uint32_t asn)
{
    send_msg(msg, g_pctrlr_sfds[asn]);
}

void send_msg_to_as(const char *msg)
{
    send_msg(msg, g_bgp_clnt_sfd);
}

static void server_handle_read_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, msg_size;
    char buffer[BUFFER_SIZE], *s_msg;
    uint8_t *u8_msg;
    server_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\nread event from sfd:%d <-> as:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    // receive msgs from socket
    while (1) {
        bytes = read(h->fd, buffer, BUFFER_SIZE);

        if (bytes == 0) {
            fprintf(stderr, "\n socket from client id %d closed [%s]\n", closure->id, __FUNCTION__);
            // TODO clean up sfd ?
            break;
        }

        // we have read all data
        if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        // read error or the remote as is close
        if (bytes == -1 || bytes == 0) {
            close(h->fd);
            free_ds(&closure->p_ds);
            free(closure);
            free(h);
            return;
        }

        //// fprintf(stdout, "\n[app] read %d bytes from as %d [%s]\n", bytes, closure->id, __FUNCTION__);

        // add received buffer to local flow buffer
        // to extract dst_id from messages
        append_ds(closure->p_ds, (uint8_t *) buffer, bytes);
    }

    while (1) {
        get_msg(closure->p_ds, &u8_msg, &msg_size);
        if (u8_msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }

        // ---------- message processing -----------
        s_msg = malloc((msg_size + 1) * sizeof *s_msg);
        memcpy(s_msg, u8_msg, msg_size);
        s_msg[msg_size] = '\0';
        if (h->fd == g_bgp_clnt_sfd) {
            handle_bgp_msg(s_msg);
        } else {
            handle_pctrlr_msg(s_msg, h->fd, g_pctrlr_sfds, g_as_num);
        }
        SAFE_FREE(s_msg);
    }
}

static void server_register_read_event_handler(int efd, int sfd)
{
    if (set_socket_non_blocking(sfd) == -1) {
        // fprintf(stdout, "\n[app] set_socket_non_blocking error [%s]\n", __FUNCTION__);
        return;
    }

    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        fprintf(stderr, "\n malloc error [%s]\n", __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = sfd;
    handler->handle = server_handle_read_event;

    server_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    closure->id = -1;   // id will be updated on receiving the first msg
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        fprintf(stderr, "\n malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->closure = closure;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

static void server_handle_listen_event(epoll_event_handler_t *h, uint32_t events)
{
    int sfd;
    struct sockaddr_in addr;
    socklen_t len;

    fprintf(stdout, "\n new connection, enter [%s]\n", __FUNCTION__);

    while (1) {
        sfd = accept(h->fd, (struct sockaddr *) &addr, &len);
        //// fprintf(stdout, "\n[app] sfd: %d [%s]\n", sfd, __FUNCTION__);
        if (sfd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                fprintf(stdout, "\n accept connection failed [%s]\n", __FUNCTION__);
                return;
            }
        } else {
            // FIXME First session will show 0.0.0.0:16384
            fprintf(stdout, "\n accept new connection from %s:%d [%s]\n", inet_ntoa(addr.sin_addr), (int) ntohs(addr.sin_port), __FUNCTION__);
            server_register_read_event_handler(h->efd, sfd);
            if (h->fd == g_bgp_serv_sfd) g_bgp_clnt_sfd == sfd;
        }
    }
}

static int server_register_listen_event_handler(int efd, char *addr, int port)
{
    int sfd;

    sfd = create_serv_socket(addr, port);
    assert(sfd != -1);

    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        fprintf(stderr, "malloc failed [%s]\n", __FUNCTION__);
        return -1;
    }
    handler->efd = efd;
    handler->fd = sfd;
    handler->handle = server_handle_listen_event;
    handler->closure = NULL;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);

    return sfd;
}

void server_init(int efd, int as_num, net_conf_t *p_ncf)
{
    int i;
    g_pctrlr_sfds = malloc(as_num * sizeof *g_pctrlr_sfds);
    for (i = 0; i < as_num; i++) {
        g_pctrlr_sfds[i] = -1;
    }
    g_as_num = as_num;

    g_bgp_serv_sfd = server_register_listen_event_handler(efd, p_ncf->bgp_serv_addr, p_ncf->bgp_serv_port);
    server_register_listen_event_handler(efd, p_ncf->pctrlr_serv_addr, p_ncf->pctrlr_serv_port);
}
