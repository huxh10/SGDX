#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"

uint32_t compute_non_transit_route(const bgp_dsrlz_msg_t)
{
}

uint32_t compute_route_by_msg_queue(const bgp_dec_msg_t *p_bgp_msg, as_policy_t *p_policies, rib_map_t **pp_ribs, uint32_t num, resp_dec_msg_t **pp_resp_dec_msgs, size_t *p_resp_msg_num, resp_dec_set_msg_t **pp_resp_dec_set_msgs, size_t *p_resp_set_msg_num)
{
    uint32_t i = 0, j = 0, orig_sender_asn = 0;
    char *key = NULL;
    rs_inner_msg_t *tmp_p_inner_msg = NULL;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;

    int potential_changes[num];
    route_node_t *p_orig_best_rn[num];
    route_node_t *p_old_best_rn[num];
    route_node_t *p_new_best_rn[num];
    for (i = 0; i < num; i++) {
        potential_changes[i] = 0;
        p_orig_best_rn[i] = NULL;
        p_old_best_rn[i] = NULL;
        p_new_best_rn[i] = NULL;
    }

    // get original sender asn and route prefix
    orig_sender_asn = p_bgp_msg->asn;
    key = my_strdup(p_bgp_msg->p_route->prefix);

    // record original rib entries
    route_list_t *p_rls[num];
    for (i = 0; i < num; i++) {
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        p_rls[i] = p_rib_entry ? p_rib_entry->rl : NULL;
        p_orig_best_rn[i] = rl_get_selected_route_node(p_rls[i]);
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
    route_cpy(&tmp_p_inner_msg->src_route, NULL, p_bgp_msg->p_route);
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
            potential_changes[i] = 1;
            p_old_best_rn[i] = rl_get_selected_route_node(p_rls[i]);
            while (pp_inner_msgs[i]) {
                // FIFO process
                tmp_p_inner_msg = pp_inner_msgs[i]->prev;

                // update entry
                if (tmp_p_inner_msg->oprt_type == ANNOUNCE) {
                    printf("iteration:%d, asn:%u, receive ANNOUNCE msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    rl_add_route(&p_rls[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy);
                } else if (tmp_p_inner_msg->oprt_type == WITHDRAW) {
                    printf("iteration:%d, asn:%u, receive WITHDRAW msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    rl_del_route(&p_rls[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy, p_old_best_rn[i]);
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
            p_new_best_rn[i] = rl_get_selected_route_node(p_rls[i]);
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
            printf("asn:%d prepares to send inner msg\n", i);
            // execute export policies and update inner msg lists 
            if (p_old_best_rn[i]) {
                printf("    old advertiser_asn:%u\n", p_old_best_rn[i]->advertiser_asn);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_old_best_rn[i]->advertiser_asn, WITHDRAW, NULL);
                if (p_old_best_rn[i]->flag.is_selected == TO_BE_DEL) {
                    free_route_ptr(&p_old_best_rn[i]->route);
                    SAFE_FREE(p_old_best_rn[i]);
                }
            }
            if (p_new_best_rn[i]) {
                printf("    new advertiser_asn:%u\n", p_new_best_rn[i]->advertiser_asn);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_new_best_rn[i]->advertiser_asn, ANNOUNCE, p_new_best_rn[i]->route);
            }
            p_old_best_rn[i] = NULL;
            p_new_best_rn[i] = NULL;
            processed_as_num_in_one_loop++;
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    SAFE_FREE(pp_inner_msgs);

    // update rib routes and prefix sets
    *p_resp_set_msg_num = 0;
    for (i = 0; i < num; i++) {
        // reuse potential_changes as change indicator for sets
        if (!potential_changes[i]) continue;
        potential_changes[i] = 0;
        if (p_rls[i]) {
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->rl = p_rls[i];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->set = NULL;
                p_rib_entry->rl = p_rls[i];
                HASH_ADD_KEYPTR(hh, pp_ribs[i], p_rib_entry->key, strlen(key), p_rib_entry);
            }
            // prefix sets
            potential_changes[i] = update_prefix_sets(&p_rib_entry->set, p_rls[i], p_policies[i].active_parts, num);
        } else {
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            if (p_rib_entry) {
                HASH_DEL(pp_ribs[i], p_rib_entry);
                SAFE_FREE(p_rib_entry->key);
                set_free(&p_rib_entry->set);
                SAFE_FREE(p_rib_entry);
                potential_changes[i] = 1;
            }
        }
        if (potential_changes[i]) (*p_resp_set_msg_num)++;
    }

    // send updated prefix sets back
    if (*p_resp_set_msg_num) {
        *pp_resp_dec_set_msgs = malloc(*p_resp_set_msg_num * sizeof **pp_resp_dec_set_msgs);
        j = 0;
        for (i = 0; i < num; i++) {
            if (!potential_changes[i]) continue;
            // XXX maybe we should avoid rib lookup
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            (*pp_resp_dec_set_msgs)[j].asn = i;
            (*pp_resp_dec_set_msgs)[j].prefix = my_strdup(key);
            (*pp_resp_dec_set_msgs)[j].set_size = p_rib_entry->set->set_size;
            (*pp_resp_dec_set_msgs)[j].set = malloc(p_rib_entry->set->set_size * sizeof *(*pp_resp_dec_set_msgs)[j].set);
            set_write_elmnts_to_array((*pp_resp_dec_set_msgs)[j].set, p_rib_entry->set);
            j++;
        }
        assert(j == *p_resp_set_msg_num);
    }

    // send updated best routes back
    *p_resp_msg_num = 0;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        p_new_best_rn[i] = rl_get_selected_route_node(p_rls[i]);
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        (*p_resp_msg_num)++;
    }
    if (!*p_resp_msg_num) return SUCCESS;
    *pp_resp_dec_msgs = malloc(*p_resp_msg_num * sizeof **pp_resp_dec_msgs);
    j = 0;
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
        } else {
            // WITHDRAW
            (*pp_resp_dec_msgs)[j].oprt_type = ANNOUNCE;
            // response msg assignment
            (*pp_resp_dec_msgs)[j].prefix = my_strdup(p_orig_best_rn[i]->route->prefix);
            (*pp_resp_dec_msgs)[j].next_hop = my_strdup(p_orig_best_rn[i]->route->next_hop);
        }
        j++;
    }
    assert(j == *p_resp_msg_num);

    return SUCCESS;
}

uint32_t update_active_parts(uint8_t *p_active_parts, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type)
{
    if (!p_active_parts || !p_parts) return SUCCESS;
    uint32_t i;
    uint8_t v = (oprt_type == ANNOUNCE) ? 1 : 0;

    for (i = 0; i < part_num; i++) {
        printf("p_parts[%d]:%u [%s]\n", i, p_parts[i], __FUNCTION__);
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

    p_tmp_rn = p_rib_entry->rl->head;
    while (p_tmp_rn) {
        if (p_active_parts[p_tmp_rn->advertiser_asn]) (*p_resp_set_size)++;
        p_tmp_rn = p_tmp_rn->next;
    }
    *pp_resp_set = malloc(*p_resp_set_size * sizeof(**pp_resp_set));
    p_tmp_rn = p_rib_entry->rl->head;
    while (p_tmp_rn) {
        if (p_active_parts[p_tmp_rn->advertiser_asn]) {
            (*pp_resp_set)[i] = p_tmp_rn->advertiser_asn;
            i++;
        }
        p_tmp_rn = p_tmp_rn->next;
    }
    assert(i == *p_resp_set_size);

    return SUCCESS;
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

uint32_t print_rs_best_ribs(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_best_rn = NULL;

    for (i = 0; i < num; i++) {
        printf("asn: %d:\n", i);
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            p_best_rn = p_rib_entry ? rl_get_selected_route_node(p_rib_entry->rl) : NULL;
            if (p_best_rn) {
                printf("advertiser_asn: %d, route: ", p_best_rn->advertiser_asn);
                print_route(p_best_rn->route);
            }
        }
    }
    return SUCCESS;
}

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_tmp_rn = NULL;

    for (i = 0; i < num; i++) {
        printf("asn: %d:\n", i);
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            p_tmp_rn = p_rib_entry->rl->head;
            while (p_tmp_rn) {
                if (p_tmp_rn->flag.is_selected) {
                    printf("[*] advertiser_asn:%d, route: ", p_tmp_rn->advertiser_asn);
                } else {
                    printf("    advertiser_asn:%d, route: ", p_tmp_rn->advertiser_asn);
                }
                print_route(p_tmp_rn->route);
                p_tmp_rn = p_tmp_rn->next;
            }
        }
    }
    return SUCCESS;
}
