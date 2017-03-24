#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "socket_utils.h"


// deprecated
void init_socket_pool(socket_pool_t *p, int size)
{
    int i;

    if (!p) {
        return;
    }

    p->size = size;
    p->used = 0;
    p->socket_info = malloc(size * sizeof *p->socket_info);
    if (!p->socket_info) {
        free(p);
        p = NULL;
        return;
    }
    for (i = 0; i < size; i++) {
        p->socket_info[i].available = 1;
    }
}

// deprecated
int is_pool_full(socket_pool_t *p)
{
    return p->size == p->used;
}

// deprecated
int add_socket_to_pool(socket_pool_t *p, struct sockaddr_in addr)
{
    int i;

    if (is_pool_full(p)) {
        return -1;
    }

    for (i = 0; i < p->size; i++) {
        if (p->socket_info[i].available) {
            p->socket_info[i].addr = addr;
            p->socket_info[i].available = 0;
            p->used++;
            return i;
        }
    }

    return -1;
}

// deprecated
void remove_socket_from_pool(socket_pool_t *p, int id)
{
    if (id >= p->size || id < 0) {
        return;
    }

    if (!p->socket_info[id].available) {
        p->socket_info[id].available = 1;
        p->used--;
    }
}

int set_socket_non_blocking(int sfd)
{
    int flags, ret;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    ret = fcntl(sfd, F_SETFL, flags);
    if (ret == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}


int create_serv_socket(char *addr, int port)
{
    int sfd, ret, reuse = 1;
    struct sockaddr_in serv_addr;

    if (!addr) {
        fprintf(stderr, "ERROR listening address is NULL [%s]\n", __FUNCTION__);
        return -1;
    }

    // IPv4, TCP, protocol (0: automatically choose)
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        fprintf(stderr, "ERROR opening socket [%s]\n", __FUNCTION__);
        return -1;
    }

    // set reuse addr and port
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "ERROR set SO_REUSEADDR [%s]\n", __FUNCTION__);
        goto err;
    }

    // bind socket and address
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_aton(addr, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(port);
    ret = bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (ret != 0) {
        fprintf(stderr, "ERROR binding socket, err:%s [%s]\n", strerror(errno), __FUNCTION__);
        goto err;
    }

    // set non blocking
    ret = set_socket_non_blocking(sfd);
    if (ret == -1) {
        fprintf(stderr, "ERROR set_socket_non_blocking [%s]\n", __FUNCTION__);
        goto err;
    }

    // listening on the socket
    ret = listen(sfd, SOMAXCONN);
    if (ret == -1) {
        perror("listen");
        goto err;
    }

    return sfd;

err:
    close(sfd);
    return -1;
}

int create_clnt_socket(char *src_addr, char *src_port, char *dest_addr, char *dest_port)
{
    int sfd, ret, reuse = 1;
    struct sockaddr_in clnt_addr, serv_addr;

    // IPv4, TCP, protocol (0: automatically choose)
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        fprintf(stderr, "ERROR opening socket [%s]\n", __FUNCTION__);
        return -1;
    }

    // set reuse addr and port
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*) &reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "ERROR set SO_REUSEADDR [%s]\n", __FUNCTION__);
        goto err;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, (const char*) &reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "ERROR set SO_REUSEPORT [%s]\n", __FUNCTION__);
        goto err;
    }
#endif

    if (src_addr) {
        // bind socket and address
        memset((char *) &clnt_addr, 0, sizeof(clnt_addr));
        clnt_addr.sin_family = AF_INET;
        inet_aton(src_addr, &clnt_addr.sin_addr);
        clnt_addr.sin_port = htons(atoi(src_port));
        ret = bind(sfd, (struct sockaddr *) &clnt_addr, sizeof(clnt_addr));
        if (ret != 0) {
            fprintf(stderr, "ERROR binding socket [%s]\n", __FUNCTION__);
            goto err;
        }
    }

    // connect to remote server
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_aton(dest_addr, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(atoi(dest_port));
    ret = connect(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        fprintf(stderr, "ERROR connect to remote server %s:%s, err: %s [%s]\n", dest_addr, dest_port, strerror(errno), __FUNCTION__);
        goto err;
    }

    // set non blocking
    ret = set_socket_non_blocking(sfd);
    if (ret == -1) {
        fprintf(stderr, "ERROR set_socket_non_blocking [%s]\n", __FUNCTION__);
        goto err;
    }

    return sfd;

err:
    close(sfd);
    return -1;
}
