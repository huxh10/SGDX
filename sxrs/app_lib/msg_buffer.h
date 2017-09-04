#ifndef _MSG_BUFFER_H_
#define _MSG_BUFFER_H_

#define INIT_SIZE 4096
#define CHUNK 4096

// dynamic string using realloc
// s[start, end)
typedef struct {
    uint8_t *s;    // base address
    int start;  // start offset of used memory
    int end;    // end offset + 1 of used memory
    int size;   // the alloced memory size
} ds_t;

typedef struct _send_msg_node send_msg_node_t;

struct _send_msg_node {
    char *msg;
    int msg_length;
    send_msg_node_t *prev;
    send_msg_node_t *next;
};

typedef struct {
    int msg_num;
    int offset;
    send_msg_node_t *head;
} sender_queue_t;

void init_ds(ds_t **pp_ds);
void free_ds(ds_t **pp_ds);
void append_ds(ds_t *p_ds, uint8_t *s, int size);
void get_msg(ds_t *p_ds, const uint8_t **msg, int *size);

#endif
