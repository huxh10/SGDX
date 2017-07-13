#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bgp.h"

char *my_strdup(const char *s)
{
    int l = strlen(s);
    char *d = malloc(l + 1);
    if (!d) return NULL;
    memcpy(d, s, l);
    d[l] = '\0';
    return d;
}

void free_route_ptr(route_t **pp_route)
{
    if (!pp_route || !*pp_route) {
        return;
    }
    SAFE_FREE((*pp_route)->prefix);
    SAFE_FREE((*pp_route)->neighbor);
    SAFE_FREE((*pp_route)->next_hop);
    SAFE_FREE((*pp_route)->origin);
    SAFE_FREE((*pp_route)->as_path.asns);
    SAFE_FREE((*pp_route)->communities);
    SAFE_FREE(*pp_route);
}

void reset_route(route_t *p_route)
{
    if (!p_route) {
        return;
    }
    SAFE_FREE(p_route->prefix);
    SAFE_FREE(p_route->neighbor);
    SAFE_FREE(p_route->next_hop);
    SAFE_FREE(p_route->origin);
    SAFE_FREE(p_route->as_path.asns);
    SAFE_FREE(p_route->communities);
    p_route->as_path.length = 0;
    p_route->med = 0;
    p_route->atomic_aggregate = 0;
}

void free_sdn_reach_output_dsrlz_msg(sdn_reach_output_dsrlz_msg_t *p_msg)
{
    SAFE_FREE(p_msg->prefix);
    SAFE_FREE(p_msg->reachability);
}

void free_bgp_route_output_dsrlz_msg(bgp_route_output_dsrlz_msg_t *p_msg)
{
    SAFE_FREE(p_msg->prefix);
    SAFE_FREE(p_msg->next_hop);
    SAFE_FREE(p_msg->as_path.asns);
}

void print_route(route_t *p_route)
{
    int i;
    if (!p_route) {
        return;
    }
    printf("prefix:%s,neighbor:%s,next_hop:%s,origin:%s,", p_route->prefix, p_route->neighbor, p_route->next_hop, p_route->origin);
    if (!p_route->as_path.length) {
        printf(" ,");
    } else {
        for (i = 0; i < p_route->as_path.length - 1; i++) {
            printf("%d ", p_route->as_path.asns[i]);
        }
        printf("%d,", p_route->as_path.asns[i]);
    }
    printf("%s,%d,%d\n", p_route->communities, p_route->med, p_route->atomic_aggregate);
}

void parse_as_path_from_file(as_path_t *p_as_path, char *p_s_as_path)
{
    int delimiter_count = 0, i;
    char *token, *p_save, *p_s_as_path_tmp;
    char *delimiter = AS_PATH_DELIMITER_STR;

    if (!p_as_path || !p_s_as_path) {
        return;
    }

    if (strlen(p_s_as_path) == 1 && p_s_as_path[0] == AS_PATH_DELIMITER_CHAR) {
        p_as_path->length = 0;
        p_as_path->asns = NULL;
        return;
    }

    p_s_as_path_tmp = p_s_as_path;
    // ensure that we have correct delimiter number in the input
    while (*p_s_as_path_tmp) {
        delimiter_count += (*p_s_as_path_tmp++ == AS_PATH_DELIMITER_CHAR);
    }

    p_as_path->length = delimiter_count + 1;
    p_as_path->asns = malloc(sizeof(*p_as_path->asns) * (p_as_path->length));

    token = strtok_r(p_s_as_path, delimiter, &p_save);
    p_as_path->asns[0] = atoi(token);
    for (i = 1; i < p_as_path->length; i++) {
        token = strtok_r(0, delimiter, &p_save);
        p_as_path->asns[i] = atoi(token);
    }
}

void parse_route_from_file(route_t **pp_route, char *p_s_route)
{
    int delimiter_count = 0;
    char *token, *p_save, *p_s_route_tmp;
    char *delimiter = ROUTE_DELIMITER_STR;

    if (!pp_route || *pp_route || !p_s_route) {
        return;
    }

    // ensure that we have correct delimiter number in the input
    p_s_route_tmp = p_s_route;
    while (*p_s_route_tmp) {
        delimiter_count += (*p_s_route_tmp++ == ROUTE_DELIMITER_CHAR);
    }
    assert(delimiter_count == ROUTE_FIELD - 1);

    *pp_route = malloc(sizeof(route_t));
    if (!*pp_route) {
        return;
    }

    token = strtok_r(p_s_route, delimiter, &p_save);
    (*pp_route)->prefix = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->neighbor = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->next_hop = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->origin = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    parse_as_path_from_file(&(*pp_route)->as_path, token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->communities = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->med = atoi(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->atomic_aggregate = atoi(token);
}

int parse_route_from_stream(route_t **pp_route, const uint8_t *p_s_route)
{
    int offset = 0;
    uint32_t size = 0;

    if (!pp_route || *pp_route || !p_s_route) {
        return 0;
    }

    *pp_route = malloc(sizeof(route_t));
    if (!*pp_route) {
        return 0;
    }

    size = *((uint8_t *) p_s_route);
    offset++;
    (*pp_route)->prefix = malloc(size + 1);
    memcpy((*pp_route)->prefix, p_s_route + offset, size);
    (*pp_route)->prefix[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->neighbor = malloc(size + 1);
    memcpy((*pp_route)->neighbor, p_s_route + offset, size);
    (*pp_route)->neighbor[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->next_hop = malloc(size + 1);
    memcpy((*pp_route)->next_hop, p_s_route + offset, size);
    (*pp_route)->next_hop[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->origin = malloc(size + 1);
    memcpy((*pp_route)->origin, p_s_route + offset, size);
    (*pp_route)->origin[size] = '\0';
    offset += size;

    size = *((uint32_t *) (p_s_route + offset));
    offset += 4;
    (*pp_route)->as_path.length = size / sizeof(int);
    (*pp_route)->as_path.asns = malloc(size);
    memcpy((*pp_route)->as_path.asns, p_s_route + offset, size);
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->communities = malloc(size + 1);
    memcpy((*pp_route)->communities, p_s_route + offset, size);
    (*pp_route)->communities[size] = '\0';
    offset += size;

    (*pp_route)->med = *((int *) (p_s_route + offset));
    offset += sizeof(int);
    (*pp_route)->atomic_aggregate = *((int *) (p_s_route + offset));
    offset += sizeof(int);
    return offset;
}

int get_route_size(route_t *r)
{
    int route_size = 0;
    if (!r) return route_size;
    route_size += strlen(r->prefix);
    route_size += strlen(r->neighbor);
    route_size += strlen(r->next_hop);
    route_size += strlen(r->origin);
    route_size += sizeof(int) * r->as_path.length;
    route_size += strlen(r->communities);
    route_size += sizeof(int);          // med
    route_size += sizeof(int);          // atomic_aggregate
    route_size += 9;                    // header count

    return route_size;
}

int write_route_to_existed_stream(uint8_t *route, route_t *input)
{
    if (!route || !input) return 0;
    int offset = 0;

    *((uint8_t *) route) = (uint8_t) strlen(input->prefix);
    offset++;
    memcpy(route + offset, input->prefix, strlen(input->prefix));
    offset += strlen(input->prefix);

    *((uint8_t *) route + offset) = (uint8_t) strlen(input->neighbor);
    offset++;
    memcpy(route + offset, input->neighbor, strlen(input->neighbor));
    offset += strlen(input->neighbor);

    *((uint8_t *) route + offset) = (uint8_t) strlen(input->next_hop);
    offset++;
    memcpy(route + offset, input->next_hop, strlen(input->next_hop));
    offset += strlen(input->next_hop);

    *((uint8_t *) route + offset) = (uint8_t) strlen(input->origin);
    offset++;
    memcpy(route + offset, input->origin, strlen(input->origin));
    offset += strlen(input->origin);

    *((uint32_t *) (route + offset)) = sizeof(*input->as_path.asns) * input->as_path.length;
    offset += 4;
    if (input->as_path.length) {
        memcpy(route + offset, input->as_path.asns, sizeof(*input->as_path.asns) * input->as_path.length);
        offset += sizeof(*input->as_path.asns) * input->as_path.length;
    }

    *((uint8_t *) route + offset) = (uint8_t) strlen(input->communities);
    offset++;
    memcpy(route + offset, input->communities, strlen(input->communities));
    offset += strlen(input->communities);

    memcpy(route + offset, &input->med, sizeof(input->med));
    offset += sizeof(input->med);

    memcpy(route + offset, &input->atomic_aggregate, sizeof(input->atomic_aggregate));
    offset += sizeof(input->atomic_aggregate);
    return offset;
}

int write_route_to_stream(uint8_t **pp_msg, route_t *input)
{
    if (!pp_msg || *pp_msg || !input) return 0;

    int route_size = get_route_size(input);
    *pp_msg = malloc(route_size);
    return write_route_to_existed_stream(*pp_msg, input);
}

int parse_bgp_ret_from_stream(bgp_route_output_dsrlz_msg_t **pp_bgp_msgs, size_t *p_bgp_msg_num, sdn_reach_output_dsrlz_msg_t **pp_sdn_msgs, size_t *p_sdn_msg_num, uint8_t *p_msg)
{
    if (!pp_bgp_msgs || *pp_bgp_msgs || !pp_sdn_msgs || *pp_sdn_msgs || !p_bgp_msg_num || !p_sdn_msg_num) {
        return 0;
    }

    uint32_t i = 0, offset = 0, tmp_size;
    *p_bgp_msg_num = *((uint32_t *) (p_msg + offset));
    offset += 4;
    *p_sdn_msg_num = *((uint32_t *) (p_msg + offset));
    offset += 4;
    if (!*p_bgp_msg_num) {
        *pp_bgp_msgs = NULL;
    } else {
        *pp_bgp_msgs = malloc(*p_bgp_msg_num * sizeof **pp_bgp_msgs);
        if (!*pp_bgp_msgs) {
            printf("malloc error for *pp_bgp_msgs [%s]\n", __FUNCTION__);
            return -1;
        }
    }
    if (!*p_sdn_msg_num) {
        *pp_sdn_msgs = NULL;
    } else {
        *pp_sdn_msgs = malloc(*p_sdn_msg_num * sizeof **pp_sdn_msgs);
        if (!*pp_sdn_msgs) {
            printf("malloc error for *pp_sdn_msgs [%s]\n", __FUNCTION__);
            return -1;
        }
    }
    for (i = 0; i < *p_bgp_msg_num; i++) {
        // asid
        (*pp_bgp_msgs)[i].asid = *((uint32_t *) (p_msg + offset));
        offset += 4;
        // next hop asid
        (*pp_bgp_msgs)[i].nh_asid = *((uint32_t *) (p_msg + offset));
        offset += 4;
        // oprt_type
        (*pp_bgp_msgs)[i].oprt_type = *(p_msg + offset);
        offset++;
        // prefix
        tmp_size = *(p_msg + offset);
        offset++;
        (*pp_bgp_msgs)[i].prefix = malloc(tmp_size + 1);
        memcpy((*pp_bgp_msgs)[i].prefix, p_msg + offset, tmp_size);
        offset += tmp_size;
        (*pp_bgp_msgs)[i].prefix[tmp_size] = '\0';
        // next_hop
        tmp_size = *(p_msg + offset);
        offset++;
        (*pp_bgp_msgs)[i].next_hop = malloc(tmp_size + 1);
        memcpy((*pp_bgp_msgs)[i].next_hop, p_msg + offset, tmp_size);
        offset += tmp_size;
        (*pp_bgp_msgs)[i].next_hop[tmp_size] = '\0';
        if ((*pp_bgp_msgs)[i].oprt_type == WITHDRAW) continue;
        // as_path
        (*pp_bgp_msgs)[i].as_path.length = *((uint32_t *) (p_msg + offset));
        offset += 4;
        tmp_size = (*pp_bgp_msgs)[i].as_path.length * sizeof *(*pp_bgp_msgs)[i].as_path.asns;
        (*pp_bgp_msgs)[i].as_path.asns = malloc(tmp_size);
        memcpy((*pp_bgp_msgs)[i].as_path.asns, p_msg + offset, tmp_size);
        offset += tmp_size;
    }
    for (i = 0; i < *p_sdn_msg_num; i++) {
        // asid
        (*pp_sdn_msgs)[i].asid = *((uint32_t *) (p_msg + offset));
        offset += 4;
        // prefix
        tmp_size = *(p_msg + offset);
        offset++;
        (*pp_sdn_msgs)[i].prefix = malloc(tmp_size + 1);
        memcpy((*pp_sdn_msgs)[i].prefix, p_msg + offset, tmp_size);
        offset += tmp_size;
        (*pp_sdn_msgs)[i].prefix[tmp_size] = '\0';
        // reachability size
        (*pp_sdn_msgs)[i].reach_size = *((uint32_t *) (p_msg + offset));
        offset += 4;
        // reachability
        tmp_size = (*pp_sdn_msgs)[i].reach_size * sizeof *(*pp_sdn_msgs)[i].reachability;
        (*pp_sdn_msgs)[i].reachability = malloc(tmp_size);
        memcpy((*pp_sdn_msgs)[i].reachability, p_msg + offset, tmp_size);
        offset += tmp_size;
    }
    return offset;
}

int write_bgp_ret_to_stream(uint8_t **pp_msg, bgp_route_output_dsrlz_msg_t *p_bgp_msgs, size_t bgp_msg_num, sdn_reach_output_dsrlz_msg_t *p_sdn_msgs, size_t sdn_msg_num)
{
    if (!pp_msg || (!p_bgp_msgs && !p_sdn_msgs)) {
        return 0;
    }

    uint32_t i = 0, offset = 0;
    size_t ret_msg_size = 0;

    // serialize the response message
    ret_msg_size += 4; // bgp_msg_num (4)
    ret_msg_size += 4; // sdn_msg_num (4)
    for (i = 0; i < bgp_msg_num; i++) {
        ret_msg_size += 9; // asid (4) + nh_asid (4) + oprt_type (1)
        ret_msg_size += 2; // prefix_size (1) + next_hop_size (1)
        ret_msg_size += strlen(p_bgp_msgs[i].prefix);
        ret_msg_size += strlen(p_bgp_msgs[i].next_hop);
        if (p_bgp_msgs[i].oprt_type == ANNOUNCE) {
            ret_msg_size += 4;  // as_path_length (4)
            ret_msg_size += p_bgp_msgs[i].as_path.length * sizeof *p_bgp_msgs[i].as_path.asns;
        }
    }
    for (i = 0; i < sdn_msg_num; i++) {
        ret_msg_size += 5; // asid (4) + prefix_size (1)
        ret_msg_size += strlen(p_sdn_msgs[i].prefix);
        ret_msg_size += 4; // reach_size (4)
        ret_msg_size += p_sdn_msgs[i].reach_size * sizeof *p_sdn_msgs[i].reachability;
    }
    *pp_msg = malloc(ret_msg_size);
    if (!*pp_msg) {
        printf("malloc error for *pp_msg [%s]\n", __FUNCTION__);
        return -1;
    }
    *((uint32_t *) (*pp_msg + offset)) = bgp_msg_num;
    offset += 4;
    *((uint32_t *) (*pp_msg + offset)) = sdn_msg_num;
    offset += 4;
    for (i = 0; i < bgp_msg_num; i++) {
        *((uint32_t *) (*pp_msg + offset)) = p_bgp_msgs[i].asid;
        offset += 4;
        *((uint32_t *) (*pp_msg + offset)) = p_bgp_msgs[i].nh_asid;
        offset += 4;
        *(*pp_msg + offset) = p_bgp_msgs[i].oprt_type;
        offset++;
        *(*pp_msg + offset) = (uint8_t) strlen(p_bgp_msgs[i].prefix);
        offset++;
        memcpy(*pp_msg + offset, p_bgp_msgs[i].prefix, strlen(p_bgp_msgs[i].prefix));
        offset += strlen(p_bgp_msgs[i].prefix);
        *(*pp_msg + offset) = (uint8_t) strlen(p_bgp_msgs[i].next_hop);
        offset++;
        memcpy(*pp_msg + offset, p_bgp_msgs[i].next_hop, strlen(p_bgp_msgs[i].next_hop));
        offset += strlen(p_bgp_msgs[i].next_hop);
        if (p_bgp_msgs[i].oprt_type == ANNOUNCE) {
            *((uint32_t *) (*pp_msg + offset)) = p_bgp_msgs[i].as_path.length;
            offset += 4;
            memcpy(*pp_msg + offset, p_bgp_msgs[i].as_path.asns, p_bgp_msgs[i].as_path.length * sizeof *p_bgp_msgs[i].as_path.asns);
            offset += p_bgp_msgs[i].as_path.length * sizeof *p_bgp_msgs[i].as_path.asns;
        }
    }
    for (i = 0; i < sdn_msg_num; i++) {
        *((uint32_t *) (*pp_msg + offset)) = p_sdn_msgs[i].asid;
        offset += 4;
        *(*pp_msg + offset) = (uint8_t) strlen(p_sdn_msgs[i].prefix);
        offset++;
        memcpy(*pp_msg + offset, p_sdn_msgs[i].prefix, strlen(p_sdn_msgs[i].prefix));
        offset += strlen(p_sdn_msgs[i].prefix);
        *((uint32_t *) (*pp_msg + offset)) = p_sdn_msgs[i].reach_size;
        offset += 4;
        memcpy(*pp_msg + offset, p_sdn_msgs[i].reachability, p_sdn_msgs[i].reach_size * sizeof *p_sdn_msgs[i].reachability);
        offset += p_sdn_msgs[i].reach_size * sizeof *p_sdn_msgs[i].reachability;
    }
    assert(offset == ret_msg_size);
    return offset;
}

// ret < 0: r2 is better, ret > 0: r1 is better
// if r1 is the same as r2, then we return r1 > r2
// r1 should be the old best route to prefer recent route
int _route_cmp(route_t *r1, route_t *r2)
{
    /*------- lowest path length -------*/
    if (r1->as_path.length > r2->as_path.length) {
        return -1;
    } else if (r1->as_path.length < r2->as_path.length) {
        return 1;
    } else {
        /*------- lowest med -------*/
        if (r1->med > r2->med) {
            return -1;
        } else if (r1->med < r2->med) {
            return 1;
        } else {
            /*------- lowest next_hop -------*/
            if (strcmp(r1->next_hop, r2->next_hop) > 0) {
                return -1;
            } else {
                return 1;
            }
        }
    }
}

void route_cpy(route_t **dst_route, uint32_t *src_asn, const route_t *src_route)
{
    if (!dst_route || !src_route) return;
    *dst_route = malloc(sizeof **dst_route);
    (*dst_route)->prefix = my_strdup(src_route->prefix);
    (*dst_route)->neighbor = my_strdup(src_route->neighbor);
    (*dst_route)->next_hop = my_strdup(src_route->next_hop);
    (*dst_route)->origin = my_strdup(src_route->origin);
    (*dst_route)->as_path.length = src_asn ? src_route->as_path.length + 1 : src_route->as_path.length;
    (*dst_route)->as_path.asns = malloc((*dst_route)->as_path.length * sizeof(int));
    if (src_asn) {
        (*dst_route)->as_path.asns[0] = *src_asn;
        memcpy((*dst_route)->as_path.asns + 1, src_route->as_path.asns, src_route->as_path.length * sizeof(int));
    } else {
        memcpy((*dst_route)->as_path.asns, src_route->as_path.asns, src_route->as_path.length * sizeof(int));
    }
    (*dst_route)->communities = my_strdup(src_route->communities);
    (*dst_route)->med = src_route->med;
    (*dst_route)->atomic_aggregate = src_route->atomic_aggregate;
}

route_node_t* rl_get_selected_route_node(route_list_t *p_rl)
{
    if (!p_rl || !p_rl->head) {
        return NULL;
    }
    route_node_t *p_tmp = p_rl->head;
    while (p_tmp) {
        if (p_tmp->flag.is_selected == 1) {
            return p_tmp;
        } else {
            p_tmp = p_tmp->next;
        }
    }
    return NULL;
}

int rl_add_route(route_list_t **pp_rl, uint32_t src_asid, route_t *src_route, uint32_t *selection_policy)
{
    if (!pp_rl) return -1;
    if (!*pp_rl) {
        *pp_rl = malloc(sizeof **pp_rl);
        (*pp_rl)->route_num = 0;
        (*pp_rl)->head = NULL;
    }
    int ret;

    // create new route node
    route_node_t *p_rn = malloc(sizeof *p_rn);
    p_rn->flag.is_selected = 0;
    p_rn->advertiser_asid = src_asid;
    p_rn->prev = NULL;
    p_rn->next = NULL;
    route_cpy(&p_rn->route, NULL, src_route);

    // add new route node to the list
    if (!(*pp_rl)->head) {
        (*pp_rl)->head = p_rn;
        p_rn->flag.is_selected = 1;
        return 0;
    }
    p_rn->next = (*pp_rl)->head;
    (*pp_rl)->head->prev = p_rn;
    (*pp_rl)->head = p_rn;
    (*pp_rl)->route_num++;

    route_node_t *tmp_rn = rl_get_selected_route_node(*pp_rl);
    assert(tmp_rn);
    ret = selection_policy[p_rn->advertiser_asid] - selection_policy[tmp_rn->advertiser_asid];
    if (ret < 0) {
        tmp_rn->flag.is_selected = 0;
        p_rn->flag.is_selected = 1;
    } else if (ret > 0) {
    } else {
        if (_route_cmp(tmp_rn->route, p_rn->route) < 0) {
            tmp_rn->flag.is_selected = 0;
            p_rn->flag.is_selected = 1;
        } else {
        }
    }
    return 0;
}

int rl_del_route(route_list_t **pp_rl, uint32_t src_asid, route_t *src_route, uint32_t *selection_policy)
{
    if (!pp_rl || !*pp_rl) return -1;
    if (!(*pp_rl)->head) {
        SAFE_FREE(*pp_rl);
        return -1;
    }
    int del_best_rn_flag = 0, ret = 0;

    // traverse and delete
    route_node_t *tmp_rn = (*pp_rl)->head;
    while (tmp_rn) {
        if (tmp_rn->advertiser_asid == src_asid && !strcmp(tmp_rn->route->neighbor, src_route->neighbor)) {
            (*pp_rl)->route_num--;
            if (tmp_rn->prev && tmp_rn->next) {
                tmp_rn->prev->next = tmp_rn->next;
                tmp_rn->next->prev = tmp_rn->prev;
            } else if (tmp_rn->next) {
                tmp_rn->next->prev = tmp_rn->prev;
                (*pp_rl)->head = tmp_rn->next;
            } else if (tmp_rn->prev) {
                tmp_rn->prev->next = tmp_rn->next;
            } else {
                (*pp_rl)->head = NULL;
                SAFE_FREE(*pp_rl);
            }
            if (tmp_rn->flag.is_selected == 1) del_best_rn_flag = 1;
            free_route_ptr(&tmp_rn->route);
            SAFE_FREE(tmp_rn);
            break;
        } else {
            tmp_rn = tmp_rn->next;
        }
    }
    if (!del_best_rn_flag) return 0;

    // the best route node has been deleted, select a new one
    if (!*pp_rl) return 0;
    route_node_t *cur_best_rn = (*pp_rl)->head;
    if (!cur_best_rn) return 0;
    tmp_rn = cur_best_rn->next;
    while (tmp_rn) {
        ret = selection_policy[cur_best_rn->advertiser_asid] - selection_policy[tmp_rn->advertiser_asid];
        if (ret > 0 || (ret = 0 && _route_cmp(cur_best_rn->route, tmp_rn->route) < 0)) {
            cur_best_rn = tmp_rn;
        }
        tmp_rn = tmp_rn->next;
    }
    cur_best_rn->flag.is_selected = 1;
    return 0;
}

// set operations
void set_free(set_t **pp_set)
{
    if (!pp_set || !*pp_set) return;
    int i;
    set_node_t *p_tmp_set, *p_iter_set = (*pp_set)->head;
    for (i = 0; i < (*pp_set)->size; i++) {
        p_tmp_set = p_iter_set;
        p_iter_set = p_iter_set->next;
        SAFE_FREE(p_tmp_set);
    }
    (*pp_set)->head = NULL;
    SAFE_FREE(*pp_set);
}

void set_write_elmnts_to_array(uint32_t *p, set_t *p_set)
{
    // no check, be careful
    int i = 0;
    set_node_t *p_iter_set = p_set->head;
    for (i = 0; i < p_set->size; i++) {
        p[i] = p_iter_set->id;
        p_iter_set = p_iter_set->next;
    }
}

static int set_add(set_t *p_set, uint32_t id)
{
    if (!p_set) return 0;
    int i;
    set_node_t *p_tmp_set = p_set->head;
    if (!p_tmp_set) {
        p_tmp_set = malloc(sizeof *p_tmp_set);
        p_tmp_set->id = id;
        p_tmp_set->prev = p_tmp_set;
        p_tmp_set->next = p_tmp_set;
        p_set->head = p_tmp_set;
        p_set->size = 1;
        return 1;
    }
    for (i = 0; i < p_set->size; i++) {
        if (p_tmp_set->id == id) return 0;
        p_tmp_set = p_tmp_set->next;
    }
    p_tmp_set = malloc(sizeof *p_tmp_set);
    p_tmp_set->id = id;
    p_tmp_set->next = p_set->head;
    p_tmp_set->prev = p_set->head->prev;
    p_set->head->prev->next = p_tmp_set;
    p_set->head->prev = p_tmp_set;
    p_set->size++;
    return 1;
}

static int set_update(set_t *p_set, uint32_t id, int *original_set, int original_size)
{
    if (!p_set) return 0;
    int i;
    set_node_t *p_tmp_set = p_set->head;
    for (i = 0; i < p_set->size; i++) {
        if (p_tmp_set->id == id) {
            if (i < original_size) original_set[i] = 1;
            return 0;
        }
        p_tmp_set = p_tmp_set->next;
    }
    p_tmp_set = malloc(sizeof *p_tmp_set);
    p_tmp_set->id = id;
    p_tmp_set->next = p_set->head;
    p_tmp_set->prev = p_set->head->prev;
    p_set->head->prev->next = p_tmp_set;
    p_set->head->prev = p_tmp_set;
    p_set->size++;
    return 1;
}

static void set_delete(set_t *p_set, int *original_set, int original_size)
{
    if (!p_set) return;
    int i;
    set_node_t *p_tmp_set, *p_iter_set = p_set->head;
    // save head ptr
    set_node_t *p_tail_set = p_set->head->prev;
    for (i = 0; i < original_size - 1; i++) {
        if (original_set[i]) {
            p_iter_set = p_iter_set->next;
            continue;
        }
        p_tmp_set = p_iter_set;
        p_iter_set = p_iter_set->next;
        p_tmp_set->next->prev = p_tmp_set->prev;
        p_tmp_set->prev->next = p_tmp_set->next;
        SAFE_FREE(p_tmp_set);
        p_set->size--;
    }
    if (original_set[i]) {
        p_set->head = p_tail_set->next;
    } else {
        if (p_set->size == 1) {
            SAFE_FREE(p_iter_set);
            p_set->size--;
            p_set->head = NULL;
        } else {
            p_set->head = p_tail_set->next;
            p_iter_set->next->prev = p_iter_set->prev;
            p_iter_set->prev->next = p_iter_set->next;
            SAFE_FREE(p_iter_set);
            p_set->size--;
        }
    }
}

int update_augmented_reach(set_t **pp_set, route_list_t *p_rl, uint8_t *p_sdn_reach)
{
    if (!p_rl || !pp_set) return 0;
    if (!*pp_set) {
        *pp_set = malloc(sizeof **pp_set);
        (*pp_set)->size = 0;
        (*pp_set)->head = NULL;
    }
    route_node_t *p_tmp_rn = p_rl->head;

    // previous set is empty, directly add asid
    if (!(*pp_set)->size) {
        while (p_tmp_rn) {
            printf("p_sdn_reach[%d]:%d [%s]\n", p_tmp_rn->advertiser_asid, p_sdn_reach[p_tmp_rn->advertiser_asid], __FUNCTION__);
            if (p_sdn_reach[p_tmp_rn->advertiser_asid]) {
                set_add(*pp_set, p_tmp_rn->advertiser_asid);
            }
            p_tmp_rn = p_tmp_rn->next;
        }
        return (*pp_set)->size ? 1 : 0;
    }

    // try to update reachability and log set change
    int i, updated_flag = 0, original_size = (*pp_set)->size;
    int original_set[original_size];
    for (i = 0; i < original_size; i++) {
        original_set[i] = 0;
    }
    while (p_tmp_rn) {
        printf("p_sdn_reach[%d]:%d [%s]\n", p_tmp_rn->advertiser_asid, p_sdn_reach[p_tmp_rn->advertiser_asid], __FUNCTION__);
        if (p_sdn_reach[p_tmp_rn->advertiser_asid]) {
            if (set_update(*pp_set, p_tmp_rn->advertiser_asid, original_set, original_size)) updated_flag = 1;
        }
        p_tmp_rn = p_tmp_rn->next;
    }
    // finish updating reachability, check if we need to delete ASes
    for (i = 0; i < original_size; i++) {
        if (!original_set[i]) {
            updated_flag = 1;
            break;
        }
    }
    if (i == original_size) return updated_flag;
    // delete the unaccessed original ASes
    set_delete(*pp_set, original_set, original_size);
    return updated_flag;
}
