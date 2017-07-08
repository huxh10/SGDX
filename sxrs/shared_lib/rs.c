#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"

uint32_t process_rib_file_line(uint32_t asid, char *line, uint32_t *tmp_asn, uint32_t *tmp_asid, route_t *p_route, rt_state_t *p_rt_states)
{
    size_t read = strlen(line);
    char *delimiter = " ", *token, *p_save, *s_tmp;

    if (!strncmp("PREFIX: ", line, 8)) {
        reset_route(p_route);
        p_route->prefix = strndup(line+8, read-9);  // "PREFIX: " is first 8 bytes, "\n" is the last byte
    } else if (!strncmp("FROM: ", line, 6)) {
        asn_map_t *asmap_entry;
        token = strtok_r(line, delimiter, &p_save);
        token = strtok_r(0, delimiter, &p_save);
        p_route->neighbor = strdup(token);
        token = strtok_r(0, delimiter, &p_save);
        *tmp_asn = atoi(token+2);                     // ASXXX
        HASH_FIND_INT(p_rt_states->as_n_2_id, tmp_asn, asmap_entry);
        *tmp_asid = asmap_entry->as_id;
    } else if (!strncmp("ORIGIN: ", line, 8)) {
        p_route->origin = strndup(line+8, read-9);  // the same as PREFIX
    } else if (!strncmp("ASPATH: ", line, 8)) {
        s_tmp = line;
        p_route->as_path.length = 0;                // delimiter count
        while (*s_tmp) {
            p_route->as_path.length += (*s_tmp++ == ' ');
        }
        p_route->as_path.asns = malloc(p_route->as_path.length * sizeof *p_route->as_path.asns);
        if (!p_route->as_path.asns) {
            printf("malloc error for p_route->as_path.asns [%s]\n", __FUNCTION__);
            return MALLOC_ERROR;
        }
        token = strtok_r(line, delimiter, &p_save);
        for (j = 0; j < p_route->as_path.length; j++) {
            token = strtok_r(0, delimiter, &p_save);
            p_route->as_path.asns[j] = atoi(token);
        }
    } else if (!strncmp("NEXT_HOP: ", line, 10)) {
        p_route->next_hop = strndup(line+10, read-11);
    } else if (!strncmp("COMMUNITY: ", line, 11)) {
        p_route->communities = strndup(line+11, read-12);
    } else if (!strncmp("ATOMIC_AGGREGATE", line, 16)) {
        p_route->atomic_aggregate = 1;
    } else if (!strncmp("MULTI_EXIT_DISC: ", line, 17)) {
        line[read-1] = 0;
        g_tmp_route->med = atoi(line+17);
    } else if (!strcmp("\n", line)) {
        rib_map_t *p_rib_entry = NULL;
        HASH_FIND_STR(p_rt_states->ribs[asid], p_route->prefix, p_rib_entry);
        if (p_rib_entry) {
            rl_add_route(&p_rib_entry->rl, *tmp_asn, *tmp_asid, p_route, p_rt_states->as_policies[asid].selection_policy);
        } else {
            p_rib_entry = malloc(sizeof *p_rib_entry);
            if (!p_rib_entry) {
                printf("malloc error for p_rib_entry [%s]\n", __FUNCTION__);
                return MALLOC_ERROR;
            }
            p_rib_entry->key = strdup(p_route->prefix);
            p_rib_entry->augmented_reach = NULL;
            p_rib_entry->rl = NULL;
            rl_add_route(&p_rib_entry->rl, *tmp_asn, *tmp_id, p_route, p_rt_states->as_policies[asid].selection_policy);
            HASH_ADD_KEYPTR(hh, p_rt_states->ribs[asid], p_rib_entry->key, strlen(p_rib_entry->key), p_rib_entry);
        }
    }
}

uint32_t process_non_transit_route(const bgp_route_input_dsrlz_msg_t *p_bgp_input_msg, rt_state_t *p_rt_states, bgp_route_output_dsrlz_msg_t **pp_bgp_output_msgs, size_t *p_bgp_output_msg_num, sdn_reach_output_dsrlz_msg_t **pp_sdn_output_msgs, size_t *p_sdn_output_msg_num)
{
    int i, j;
    uint8_t next_hop_changed[p_rt_states->as_size];
    uint8_t reach_changed[p_rt_states->as_size];
    route_node_t *p_old_rn[p_rt_states->as_size];
    route_node_t *p_new_rn[p_rt_states->as_size];
    rib_map_t *p_rib_entry = NULL;

    *p_bgp_output_msg_num = 0;
    *p_sdn_output_msg_num = 0;

    for (i = 0; i < p_rt_states->as_size; i++) {
        next_hop_changed[i] = 0;
        reach_changed[i] = 0;

        // execute filter policies
        if (!p_rt_states->as_policies[p_bgp_input_msg->asid].export_policy[i]) continue;
        if (!p_rt_states->as_policies[i].import_policy[p_bgp_input_msg->asid]) continue;

        // update ribs
        HASH_FIND_STR(p_rt_states->ribs[i], p_bgp_input_msg->p_route->prefix, p_rib_entry);
        if (!p_rib_entry) {
            assert(p_bgp_input_msg->oprt_type == ANNOUNCE);
            p_rib_entry = malloc(sizeof *p_rib_entry);
            if (!p_rib_entry) {
                printf("malloc error for p_rib_entry [%s]\n", __FUNCTION__);
                return MALLOC_ERROR;
            }
            p_rib_entry->key = my_strdup(p_bgp_input_msg->p_route->prefix);
            p_rib_entry->augmented_reach = NULL;
            p_rib_entry->rl = NULL;
            p_old_rn[i] = NULL;
            rl_add_route(&p_rib_entry->rl, p_bgp_input_msg->asn, p_bgp_input_msg->asid, p_bgp_msg->p_route, p_rt_states->as_policies[i].selection_policy);
            p_new_rn[i] = rl_get_selected_route_node(p_rib_entry->rl);
            HASH_ADD_KEYPTR(hh, p_rt_states->ribs[i], p_rib_entry->key, strlen(key), p_rib_entry);
        } else {
            // get next hop asid before processing
            p_old_rn[i] = rl_get_selected_route_node(p_rib_entry->rl);
            // update route
            if (p_bgp_input_msg->oprt_type == ANNOUNCE) {
                rl_add_route(&p_rib_entry->rl, p_bgp_input_msg->asn, p_bgp_input_msg->asid, p_bgp_msg->p_route, p_rt_states->as_policies[i].selection_policy);
            } else if (p_bgp_input_msg->oprt_type == WITHDRAW) {
                rl_del_route(&p_rib_entry->rl, p_bgp_input_msg->asn, p_bgp_msg->p_route, p_rt_states->as_policies[i].selection_policy);
            }
            p_new_rn[i] = rl_get_selected_route_node(p_rib_entry->rl);
        }
        // get change status
        if (i != p_bgp_input_msg->asid) {
            if (p_old_rn[i] != p_new_rn[i]) {
                next_hop_changed[i] = 1;
                (*p_bgp_output_msg_num)++;
            }
            if (ENABLE_SDX) {
                reach_changed[i] = update_augmented_reach(&p_rib_entry->augmented_reach, p_rib_entry->rl, p_rt_states->sdn_orgnl_reach);
                *p_sdn_output_msg_num += reach_changed[i];
            }
        }
    }

    // return bgp route output msg
    *pp_bgp_output_msgs = malloc(*p_bgp_output_msg_num * sizeof **pp_bgp_output_msgs);
    if (!*pp_bgp_output_msgs) {
        printf("malloc error for pp_bgp_output_msgs [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    j = 0;
    for (i = 0; i < p_rt_states->as_size; i++) {
        if (!next_hop_changed[i]) continue;
        (*pp_bgp_output_msgs)[j].asid = i;
        // assume the new announcement route can overwrite
        // the previous next hop route in AS border router
        if (p_new_rn[i]) {
            // ANNOUNCE
            (*pp_bgp_output_msgs)[j].oprt_type = ANNOUNCE;
            (*pp_bgp_output_msgs)[j].prefix = my_strdup(p_new_rn[i]->route->prefix);
            (*pp_bgp_output_msgs)[j].next_hop = my_strdup(p_new_rn[i]->route->next_hop);
            (*pp_bgp_output_msgs)[j].as_path.length = p_new_rn[i]->route->as_path.length;
            (*pp_bgp_output_msgs)[j].as_path.asns = malloc((*pp_bgp_output_msgs)[j].as_path.length * sizeof *(*pp_bgp_output_msgs)[j].as_path.asns);
            if (!(*pp_bgp_output_msgs)[j].as_path.asns) {
                printf("malloc error for (*pp_bgp_output_msgs)[%d].as_path.asns [%s]\n", j, __FUNCTION__);
                return MALLOC_ERROR;
            }
            memcpy((*pp_bgp_output_msgs)[j].as_path.asns, p_new_rn[i]->route->as_path.asns, (*pp_bgp_output_msgs)[j].as_path.length * sizeof *(*pp_bgp_output_msgs)[j].as_path.asns);
        } else {
            // WITHDRAW
            (*pp_bgp_output_msgs)[j].oprt_type = WITHDRAW;
            (*pp_bgp_output_msgs)[j].prefix = my_strdup(p_old_rn[i]->route->prefix);
            (*pp_bgp_output_msgs)[j].next_hop = my_strdup(p_old_rn[i]->route->next_hop);
        }
        j++;
    }
    assert(j == *p_bgp_output_msg_num);

    if (!ENABLE_SDX || !*p_sdn_output_msg_num) return SUCCESS;
    // return sdn reachability output msg
    *pp_sdn_output_msgs = malloc(*p_sdn_output_msg_num * sizeof **pp_sdn_output_msgs);
    if (!*pp_sdn_output_msgs) {
        printf("malloc error for *pp_sdn_output_msgs [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    j = 0;
    for (i = 0; i < p_rt_states->as_size; i++) {
        if (!reach_changed[i]) continue;
        HASH_FIND_STR(p_rt_states->ribs[i], p_bgp_input_msg->p_route->prefix, p_rib_entry);
        (*pp_sdn_output_msgs)[j].asid = i;
        (*pp_sdn_output_msgs)[j].prefix = my_strdup(p_bgp_input_msg->p_route->prefix);
        (*pp_sdn_output_msgs)[j].reach_size = p_rib_entry->augmented_reach->size;
        (*pp_sdn_output_msgs)[j].reachability = malloc((*pp_sdn_output_msgs)[j].reach_size * sizeof *(*pp_sdn_output_msgs)[j].reachability);
        set_write_elmnts_to_array((*pp_sdn_output_msgs)[j].reachability, p_rib_entry->augmented_reach);
        j++;
    }
    assert(j == *p_sdn_output_msg_num);

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
