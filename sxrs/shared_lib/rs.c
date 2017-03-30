#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"

uint32_t compute_route_by_msg_queue(bgp_dec_msg_t *p_bgp_msg, as_policy_t *p_policies, rib_map_t **pp_ribs, uint32_t num, resp_dec_msg_t **pp_resp_dec_msgs, size_t *p_resp_msg_num)
{
    uint32_t i = 0, j = 0, orig_sender_asn = 0;
    char *key = NULL;
    rs_inner_msg_t *tmp_p_inner_msg = NULL;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;

    // TODO change pointer to uuid
    route_node_t *p_orig_best_rn[num];
    route_node_t *p_old_best_rn[num];
    route_node_t *p_new_best_rn[num];
    for (i = 0; i < num; i++) {
        p_orig_best_rn[i] = NULL;
        p_old_best_rn[i] = NULL;
        p_new_best_rn[i] = NULL;
    }

    // get original sender asn and route prefix
    orig_sender_asn = p_bgp_msg->asn;
    key = my_strdup(p_bgp_msg->p_route->prefix);

    // record original rib entries
    route_node_t *p_curr_rns[num];
    for (i = 0; i < num; i++) {
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        p_curr_rns[i] = p_rib_entry ? p_rib_entry->routes : NULL;
        p_orig_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
    }

    // initialize inner msg lists for exchange
    rs_inner_msg_t **pp_inner_msgs = malloc(num * sizeof *pp_inner_msgs);
    for (i = 0; i < num; i++) {
        pp_inner_msgs[i] = NULL;
    }

    // add received bgp_msg to asn list
    tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
    tmp_p_inner_msg->src_asn = p_bgp_msg->p_route->as_path.asns[0];
    tmp_p_inner_msg->oprt_type = p_bgp_msg->oprt_type;
    tmp_p_inner_msg->src_route = p_bgp_msg->p_route;
    tmp_p_inner_msg->next = tmp_p_inner_msg;
    tmp_p_inner_msg->prev = tmp_p_inner_msg;
    pp_inner_msgs[orig_sender_asn] = tmp_p_inner_msg;

    while (1) {
        // iterate until routes are converged
        iteration++;
        processed_as_num_in_one_loop = 0;

        // process msgs to each as
        for (i = 0; i < num; i++) {
            if (pp_inner_msgs[i] == NULL) continue;
            p_old_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
            while (pp_inner_msgs[i]) {
                // FIFO process
                tmp_p_inner_msg = pp_inner_msgs[i]->prev;

                // update entry
                if (tmp_p_inner_msg->oprt_type == ANNOUNCE) {
                    //printf("iteration:%d, asn:%u, receive ANNOUNCE msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    add_route(&p_curr_rns[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy);
                } else if (tmp_p_inner_msg->oprt_type == WITHDRAW) {
                    //printf("iteration:%d, asn:%u, receive WITHDRAW msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    del_route(&p_curr_rns[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy, p_old_best_rn[i]);
                }

                if (pp_inner_msgs[i]->prev == pp_inner_msgs[i]) {
                    free_route_ptr(&tmp_p_inner_msg->src_route);
                    SAFE_FREE(tmp_p_inner_msg);
                    pp_inner_msgs[i] = NULL;
                } else {
                    pp_inner_msgs[i]->prev = tmp_p_inner_msg->prev;
                    tmp_p_inner_msg->prev->next = pp_inner_msgs[i];
                    free_route_ptr(&tmp_p_inner_msg->src_route);
                    SAFE_FREE(tmp_p_inner_msg);
                }
            }
            p_new_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
            /*
            if (p_new_best_rn[i]) {
                printf("as:%d new best after this iteration: ", i);
                print_route(p_new_best_rn[i]->route);
            } else {
                printf("as:%d new best after this iteration: NULL\n", i);
            }
            */
        }
        // add potential msgs to next iteration
        for (i = 0; i < num; i++) {
            if (p_old_best_rn[i] == p_new_best_rn[i]) continue;
            //printf("asn:%d prepares to send inner msg\n", i);
            // execute export policies and update inner msg lists 
            if (p_old_best_rn[i]) {
                //printf("    old next_hop:%u\n", p_old_best_rn[i]->next_hop);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_old_best_rn[i]->next_hop, WITHDRAW, NULL);
                if (p_old_best_rn[i]->is_selected == TO_BE_DEL) {
                    free_route_ptr(&p_old_best_rn[i]->route);
                    SAFE_FREE(p_old_best_rn[i]);
                }
            }
            if (p_new_best_rn[i]) {
                //printf("    new next_hop:%u\n", p_new_best_rn[i]->next_hop);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_new_best_rn[i]->next_hop, ANNOUNCE, p_new_best_rn[i]->route);
            }
            p_old_best_rn[i] = NULL;
            p_new_best_rn[i] = NULL;
            processed_as_num_in_one_loop++;
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    SAFE_FREE(pp_inner_msgs);

    // update the sender rib
    p_new_best_rn[orig_sender_asn] = get_selected_route_node(p_curr_rns[orig_sender_asn]);
    if (p_orig_best_rn[orig_sender_asn] != p_new_best_rn[orig_sender_asn]) {
        if (p_new_best_rn[orig_sender_asn]) {
            HASH_FIND_STR(pp_ribs[orig_sender_asn], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->routes = p_curr_rns[orig_sender_asn];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->routes = p_curr_rns[orig_sender_asn];
                HASH_ADD_KEYPTR(hh, pp_ribs[orig_sender_asn], p_rib_entry->key, strlen(key), p_rib_entry);
            }
        } else {
            HASH_FIND_STR(pp_ribs[orig_sender_asn], key, p_rib_entry);
            HASH_DEL(pp_ribs[orig_sender_asn], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
        }
    }

    // send updated routes back and update related ribs
    *p_resp_msg_num = 0;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        p_new_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        (*p_resp_msg_num)++;
    }
    if (!*p_resp_msg_num) return SUCCESS;
    *pp_resp_dec_msgs = malloc(*p_resp_msg_num * sizeof **pp_resp_dec_msgs);

    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        (*pp_resp_dec_msgs)[j].asn = i;
        if (p_new_best_rn[i]) {
            // ANNOUNCE
            (*pp_resp_dec_msgs)[j].oprt_type = ANNOUNCE;
            // response msg assignment
            (*pp_resp_dec_msgs)[j].prefix = my_strdup(p_new_best_rn[i]->route->prefix);
            (*pp_resp_dec_msgs)[j].next_hop = my_strdup(p_new_best_rn[i]->route->next_hop);
            (*pp_resp_dec_msgs)[j].as_path.length = p_new_best_rn[i]->route->as_path.length;
            (*pp_resp_dec_msgs)[j].as_path.asns = malloc((*pp_resp_dec_msgs)[j].as_path.length * sizeof *(*pp_resp_dec_msgs)[j].as_path.asns);
            memcpy((*pp_resp_dec_msgs)[j].as_path.asns, p_new_best_rn[i]->route->as_path.asns, (*pp_resp_dec_msgs)[j].as_path.length * sizeof *(*pp_resp_dec_msgs)[j].as_path.asns);
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->routes = p_curr_rns[i];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->routes = p_curr_rns[i];
                HASH_ADD_KEYPTR(hh, pp_ribs[i], p_rib_entry->key, strlen(key), p_rib_entry);
            }
        } else {
            // WITHDRAW
            (*pp_resp_dec_msgs)[j].oprt_type = ANNOUNCE;
            // response msg assignment
            (*pp_resp_dec_msgs)[j].prefix = my_strdup(p_orig_best_rn[i]->route->prefix);
            (*pp_resp_dec_msgs)[j].next_hop = my_strdup(p_orig_best_rn[i]->route->next_hop);
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            HASH_DEL(pp_ribs[i], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
        }
        j++;
    }

    return SUCCESS;
}

uint32_t update_active_parts(uint8_t *p_active_parts, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type)
{
    if (!p_active_parts || !p_parts) return SUCCESS;
    uint32_t i;
    uint8_t v = (oprt_type == ANNOUNCE) ? 1 : 0;

    for (i = 0; i < part_num; i++) {
        p_active_parts[p_parts[i]] = v;
    }

    return SUCCESS;
}


uint32_t get_prefix_set(const char *prefix, uint8_t *p_active_parts, uint32_t num, rib_map_t *p_rib, uint32_t **pp_resp_set, uint32_t *p_resp_set_size)
{
    if (!pp_resp_set || *pp_resp_set || !p_resp_set_size|| !prefix) {
        return SUCCESS;
    }
    rib_map_t *p_rib_entry = NULL;
    route_node_t *p_tmp_rn = NULL;
    *p_resp_set_size = 0;
    uint32_t i = 0;

    HASH_FIND_STR(p_rib, prefix, p_rib_entry);
    if (!p_rib_entry) return SUCCESS;

    p_tmp_rn = p_rib_entry->routes;
    while (p_tmp_rn) {
        if (p_active_parts[p_tmp_rn->next_hop]) (*p_resp_set_size)++;
        p_tmp_rn = p_tmp_rn->next;
    }
    *pp_resp_set = malloc(*p_resp_set_size * sizeof(**pp_resp_set));
    p_tmp_rn = p_rib_entry->routes;
    while (p_tmp_rn) {
        if (p_active_parts[p_tmp_rn->next_hop]) {
            (*pp_resp_set)[i] = p_tmp_rn->next_hop;
            i++;
        }
        p_tmp_rn = p_tmp_rn->next;
    }
    assert(i = *p_resp_set_size);

    return NULL;
}

uint32_t get_rs_ribs_num(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i, count = 0;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_best_rn = NULL;

    for (i = 0; i < num; i++) {
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            count++;
        }
    }
    printf("total ribs entry num: %d\n", count);
    return SUCCESS;

}

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_best_rn = NULL;

    for (i = 0; i < num; i++) {
        printf("asn: %d:\n", i);
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            p_best_rn = p_rib_entry ? get_selected_route_node(p_rib_entry->routes) : NULL;
            if (p_best_rn) {
                printf("next_hop: %d, route: ", p_best_rn->next_hop);
                print_route(p_best_rn->route);
            }
        }
    }
    return SUCCESS;
}
