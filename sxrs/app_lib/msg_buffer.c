#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "msg_buffer.h"

void init_ds(ds_t **pp_ds)
{
    if (pp_ds == NULL || *pp_ds != NULL) {
        return;
    }

    *pp_ds = (ds_t *) malloc(sizeof(ds_t));
    if (*pp_ds == NULL) {
        return;
    }

    (*pp_ds)->size = INIT_SIZE;
    (*pp_ds)->start = 0;
    (*pp_ds)->end = 0;
    (*pp_ds)->s = malloc((*pp_ds)->size);
    if ((*pp_ds)->s == NULL) {
        free(*pp_ds);
        *pp_ds = NULL;
        return;
    }
}

void free_ds(ds_t **pp_ds)
{
    if (!pp_ds || !(*pp_ds)) {
        return;
    }

    if (!(*pp_ds)->s) {
        free((*pp_ds)->s);
    }

    free(*pp_ds);
    *pp_ds = NULL;
}

void append_ds(ds_t *p_ds, uint8_t *s, int size)
{
    int more = 0;

    if (p_ds == NULL || s == NULL || size == 0) {
        return;
    }

    //fprintf(stdout, "\nds curse before appended [%d, %d) [%s]\n", p_ds->start, p_ds->end, __FUNCTION__);

    more = size - (p_ds->size - p_ds->end);

    if (more > 0) {
        p_ds->size = p_ds->size + ((more / CHUNK) + 1) * CHUNK;
        p_ds->s = realloc(p_ds->s, p_ds->size);
    }

    memcpy(p_ds->s + p_ds->end, s, size);
    p_ds->end = p_ds->end + size;
    //fprintf(stdout, "\nds curse after appended [%d, %d) [%s]\n", p_ds->start, p_ds->end, __FUNCTION__);
}

void get_msg(ds_t *p_ds, const uint8_t **pp_msg, int *p_size)
{
    int msg_len;

    if (!p_ds || !pp_msg || !p_size) {
        return;
    }

    *pp_msg = NULL;
    *p_size = 0;

    // no msgs exist
    if (p_ds->end == p_ds->start) {
        p_ds->start = 0;
        p_ds->end = 0;
        return;
    }

    // only one byte, move to offset 0
    if (p_ds->end == (p_ds->start + 1)) {
        if (p_ds->start != 0) {
            memcpy(p_ds->s, p_ds->s + p_ds->start, 1);
            p_ds->start = 0;
            p_ds->end = 1;
        }
        return;
    }

    // the first two bytes of a msg should be the msg length
    msg_len = *((uint16_t *) (p_ds->s + p_ds->start));
    //fprintf(stdout, "\nmsg_len: %d [%s]\n", msg_len, __FUNCTION__);

    // complete msgs have beed processed, move incomplete msg to offset 0
    if (p_ds->start + msg_len > p_ds->end) {
        if (p_ds->start != 0) {
            memcpy(p_ds->s, p_ds->s + p_ds->start, p_ds->end - p_ds->start);
            p_ds->start = 0;
            p_ds->end = p_ds->end - p_ds->start;
        }
        return;
    }

    // complete msgs exist, process one
    *pp_msg = p_ds->s + p_ds->start;
    *p_size = msg_len;
    p_ds->start = p_ds->start + msg_len;
    return;
}
