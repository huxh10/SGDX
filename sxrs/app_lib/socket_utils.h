#ifndef _SOCKET_UTILS_H_
#define _SOCKET_UTILS_H_

typedef struct {
    struct sockaddr_in addr;
    int available;
} socket_info_t;

typedef struct {
    socket_info_t *socket_info;
    int used;
    int size;
} socket_pool_t;

void init_socket_pool(socket_pool_t *p, int size);
int is_pool_full(socket_pool_t *p);
int add_socket_to_pool(socket_pool_t *p, struct sockaddr_in addr);
void remove_socket_from_pool(socket_pool_t *p, int id);
int set_socket_non_blocking(int sfd);
int create_serv_socket(char *addr, int port);
int create_clnt_socket(char *src_addr, char *src_port, char *dest_addr, char *dest_port);

#endif
