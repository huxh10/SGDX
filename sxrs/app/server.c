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
#include "time_utils.h"
#include "msg_buffer.h"
#include "app_types.h"
#include "msg_handler.h"
#include "server.h"
#include "bgp.h"

typedef struct {
    uint32_t id;
    ds_t *p_ds;
} server_read_closure_t;

int g_as_size = 0;
int g_bgp_serv_sfd, g_bgp_clnt_sfd;
FILE *g_result_fp;
int g_route_id = 0;
uint64_t g_start_time = 0, g_end_time = 0;
sender_queue_t *gp_sender_queues = NULL;
epoll_event_handler_t **gpp_ehs = NULL;

static void check_to_exit()
{
    if (g_route_id != -1) return;
    int i;
    for (i = 0; i < g_as_size; i++) {
        if (gp_sender_queues[i].msg_num != 0) return;
    }
    exit(0);
}

static inline int send_msg(int id, int sfd)
{
    // return value: 1, stop EPOLLOUT; 0, continue EPOLLOUT
    int i, sent, bytes, offset = 0;
    send_msg_node_t *p_tmp_mn;

    if (sfd < 0) {
        fprintf(stdout, "Currently, the connection doesn't exist [%s]\n", __FUNCTION__);
        return 0;
    }

    //fprintf(stdout, "\nmsg: [%s] [%s]\n", msg, __FUNCTION__);

    while (gp_sender_queues[id].msg_num != 0) {
        while (gp_sender_queues[id].head->msg_length != gp_sender_queues[id].offset) {
            bytes = gp_sender_queues[id].head->msg_length - gp_sender_queues[id].offset;
            if ((sent = write(sfd, gp_sender_queues[id].head->msg + gp_sender_queues[id].offset, bytes)) == -1) {
                if (errno == EAGAIN) {
                    return 0;
                    //fprintf(stdout, "[app-sleep] write mqueue failed dst_sfd:%d, err: %s [%s]\n", sfd, strerror(errno), __FUNCTION__);
                } else {
                    fprintf(stdout, "write socket failed dst_sfd:%d, err: %s [%s]\n", sfd, strerror(errno), __FUNCTION__);
                    return 1;
                }
            }
            //fprintf(stdout, "write socket %d/%d bytes successfully, to sfd %d [%s]\n", sent, bytes, sfd, __FUNCTION__);
            gp_sender_queues[id].offset += sent;
        }
        gp_sender_queues[id].offset = 0;
        free(gp_sender_queues[id].head->msg);
        if (gp_sender_queues[id].head->next == gp_sender_queues[id].head) {
            SAFE_FREE(gp_sender_queues[id].head);
            gp_sender_queues[id].msg_num = 0;
        } else {
            gp_sender_queues[id].head->next->prev = gp_sender_queues[id].head->prev;
            gp_sender_queues[id].head->prev->next = gp_sender_queues[id].head->next;
            p_tmp_mn = gp_sender_queues[id].head;
            gp_sender_queues[id].head = gp_sender_queues[id].head->next;
            SAFE_FREE(p_tmp_mn);
            gp_sender_queues[id].msg_num--;
        }
    }
    check_to_exit();
    return 1;
}

void send_msg_to_as(const char *msg)
{
    uint32_t msg_len = strlen(msg) + 2;
    char *msg_with_header = malloc(msg_len);
    memcpy(msg_with_header, &msg_len, 2);
    memcpy(msg_with_header + 2, msg, msg_len - 2);
    free(msg_with_header);
    // NOTE: fake sending for performance tests
    //send_msg(msg_with_header, msg_len, g_bgp_clnt_sfd);
}

static void server_handle_comm_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, msg_size;
    char buffer[BUFFER_SIZE], *s_msg;
    const uint8_t *u8_msg = NULL;
    server_read_closure_t *closure = h->closure;

    if (events & EPOLLOUT) {
        if (send_msg(closure->id, h->fd)) {
            // sending msg done, mqueue is empty, stop EPOLLOUT
            epoll_ctl_handler(h, EPOLL_CTL_MOD, EPOLLIN | EPOLLET | EPOLLRDHUP);
        }
    }

    if (!(events & EPOLLIN)) {
        return;
    }

    //fprintf(stdout, "\nread event for sfd:%d client_id:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    // receive msgs from socket
    while (1) {
        bytes = read(h->fd, buffer, BUFFER_SIZE);

        if (bytes == 0) {
            fprintf(stderr, "socket from sfd:%d client_id:%d closed by peer [%s]\n", h->fd, closure->id, __FUNCTION__);
            close(h->fd);
            break;
        }

        // we have read all data
        if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        // read error or the remote as is close
        if (bytes == -1) {
            fprintf(stderr, "socket from sfd:%d client_id:%d err:%s [%s]\n", h->fd, closure->id, strerror(errno), __FUNCTION__);
            close(h->fd);
            free_ds(&closure->p_ds);
            free(closure);
            free(h);
            return;
        }

        //fprintf(stdout, "read %d bytes from sfd:%d client_id:%d [%s]\n", bytes, h->fd, closure->id, __FUNCTION__);

        // add received buffer to local flow buffer
        // to extract dst_id from messages
        append_ds(closure->p_ds, (uint8_t *) buffer, bytes);
    }

    while (1) {
        get_msg(closure->p_ds, &u8_msg, &msg_size);
        if (!u8_msg || msg_size == 0) {
            // we have processed all available msgs
            //printf("finish msg processing [%s]\n", __FUNCTION__);
            break;
        }

        // ---------- message processing -----------
        g_start_time = get_us_time();
        s_msg = malloc((msg_size - 2 + 1) * sizeof *s_msg);
        memcpy(s_msg, u8_msg + 2, msg_size -2);
        s_msg[msg_size - 2] = '\0';
        if (h->fd == g_bgp_clnt_sfd) {
            //printf("handle_exabgp_msg:%s [%s]\n", s_msg, __FUNCTION__);
            g_route_id = handle_exabgp_msg(s_msg);
            check_to_exit();
            g_end_time = get_us_time();
            fprintf(g_result_fp, "latency: %lu\n", g_end_time - g_start_time);
            fflush(g_result_fp);
        }
        // -----------------------------------------
    }
}

static void server_register_comm_event_handler(int efd, int sfd)
{
    if (set_socket_non_blocking(sfd) == -1) {
        // fprintf(stdout, "\n[app] set_socket_non_blocking error [%s]\n", __FUNCTION__);
        return;
    }

    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        fprintf(stderr, "\nmalloc error [%s]\n", __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = sfd;
    handler->handle = server_handle_comm_event;

    server_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    closure->id = -1;   // id will be updated on receiving the first msg
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        fprintf(stderr, "\nmalloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->closure = closure;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

static void server_handle_listen_event(epoll_event_handler_t *h, uint32_t events)
{
    int sfd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr);

    fprintf(stdout, "\nnew connection from socket:%d, enter [%s]\n", h->fd, __FUNCTION__);

    while (1) {
        sfd = accept(h->fd, (struct sockaddr *) &addr, &len);
        //// fprintf(stdout, "\n[app] sfd: %d [%s]\n", sfd, __FUNCTION__);
        if (sfd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                fprintf(stdout, "accept connection failed, err:%s [%s]\n", strerror(errno), __FUNCTION__);
                return;
            }
        } else {
            // FIXME First session will be 0.0.0.0:16384?
            fprintf(stdout, "accept new connection sfd:%d from %s:%d [%s]\n", sfd, inet_ntoa(addr.sin_addr), (int) ntohs(addr.sin_port), __FUNCTION__);
            server_register_comm_event_handler(h->efd, sfd);
            if (h->fd == g_bgp_serv_sfd) {
                fprintf(stdout, "bgp_clnt_sfd is %d [%s]\n", sfd, __FUNCTION__);
                g_bgp_clnt_sfd = sfd;
            }
        }
    }
}

static int server_register_listen_event_handler(int efd, char *addr, int port)
{
    int sfd;

    sfd = create_serv_socket(addr, port);
    fprintf(stdout, "socket:%d starts to listen on %s:%d [%s]\n", sfd, addr, port, __FUNCTION__);
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

void server_init(int efd, net_conf_t *p_ncf, int as_size)
{
    g_bgp_serv_sfd = server_register_listen_event_handler(efd, p_ncf->bgp_serv_addr, p_ncf->bgp_serv_port);
    server_register_listen_event_handler(efd, p_ncf->pctrlr_serv_addr, p_ncf->pctrlr_serv_port);
    if ((g_result_fp = fopen(RESULT_FILE, "w+")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", RESULT_FILE, __FUNCTION__);
        exit(-1);
    }
    g_as_size = as_size;
    gp_sender_queues = malloc(as_size * sizeof *gp_sender_queues);
    gpp_ehs = malloc(as_size * sizeof * gpp_ehs);
    int i;
    for (i = 0; i < as_size; i++) {
        gp_sender_queues[i].msg_num = 0;
        gp_sender_queues[i].offset = 0;
        gp_sender_queues[i].head = NULL;
        gpp_ehs[i] = NULL;
    }
}
