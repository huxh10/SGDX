#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "shared_types.h"
#include "bgp.h"
#include "rs.h"

uint32_t load_asmap(rt_state_t **pp_rt_states, uint32_t as_size, uint32_t *as_id_2_n)
{
    uint32_t i;
    asn_map_t *asmap_entry;

    if (!pp_rt_states) return INPUT_NULL_POINTER;

    if (!*pp_rt_states) {
        *pp_rt_states = malloc(sizeof **pp_rt_states);
        if (!*pp_rt_states) {
            printf("malloc error for *pp_rt_states [%s]\n", __FUNCTION__);
            return MALLOC_ERROR;
        }
    }

    // copy as_id_2_n
    (*pp_rt_states)->as_size = as_size;
    (*pp_rt_states)->as_id_2_n = malloc(as_size * sizeof *(*pp_rt_states)->as_id_2_n);
    if (!(*pp_rt_states)->as_id_2_n) {
        printf("malloc error for (*pp_rt_states)->as_id_2_n [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    memcpy((*pp_rt_states)->as_id_2_n, as_id_2_n, as_size * sizeof *as_id_2_n);

    // construct asn_2_id map
    (*pp_rt_states)->as_n_2_id = NULL;
    for (i = 0; i < as_size; i++) {
        asmap_entry = malloc(sizeof *asmap_entry);
        if (!asmap_entry) {
            printf("malloc error for asmap_entry, id:%d [%s]\n", i, __FUNCTION__);
            return MALLOC_ERROR;
        }
        asmap_entry->as_n = (*pp_rt_states)->as_id_2_n[i];
        asmap_entry->as_id = i;
        HASH_ADD_INT((*pp_rt_states)->as_n_2_id, as_n, asmap_entry);
    }

    // allocate memory for the rest states
    (*pp_rt_states)->as_policies = malloc(as_size * sizeof *(*pp_rt_states)->as_policies);
    (*pp_rt_states)->sdn_orgnl_reach = malloc(as_size * as_size * sizeof *(*pp_rt_states)->sdn_orgnl_reach);
    (*pp_rt_states)->ribs = malloc(as_size * sizeof *(*pp_rt_states)->ribs);
    if (!(*pp_rt_states)->as_policies || !(*pp_rt_states)->sdn_orgnl_reach || !(*pp_rt_states)->ribs) {
        printf("malloc error for (*pp_rt_states) rest states [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    for (i = 0; i < as_size * as_size; i++) {
        // set default value false
        (*pp_rt_states)->sdn_orgnl_reach[i] = 0;
    }
    return SUCCESS;
}

uint32_t process_rib_file_line(uint32_t asid, char *line, uint32_t *tmp_asid, route_t *p_route, rt_state_t *p_rt_states)
{
    size_t read = strlen(line);
    char *delimiter = " ", *token, *p_save, *s_tmp;
    uint32_t j, asn;

    if (!strncmp("PREFIX: ", line, 8)) {
        reset_route(p_route);
        p_route->prefix = strndup(line+8, read-9);  // "PREFIX: " is first 8 bytes, "\n" is the last byte
    } else if (!strncmp("FROM: ", line, 6)) {
        line[read-1] = 0;                           // strip '\n'
        asn_map_t *asmap_entry;
        token = strtok_r(line, delimiter, &p_save);
        token = strtok_r(0, delimiter, &p_save);
        p_route->neighbor = my_strdup(token);
        token = strtok_r(0, delimiter, &p_save);
        asn = atoi(token+2);                   // ASXXX
        HASH_FIND_INT(p_rt_states->as_n_2_id, &asn, asmap_entry);
        *tmp_asid = asmap_entry->as_id;
    } else if (!strncmp("ORIGIN: ", line, 8)) {
        p_route->origin = strndup(line+8, read-9);  // the same as PREFIX
    } else if (!strncmp("ASPATH: ", line, 8)) {
        line[read-1] = 0;                           // strip '\n'
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
        line[read-1] = 0;                           // strip '\n'
        p_route->med = atoi(line+17);
    } else if (!strcmp("\n", line)) {
        rib_map_t *p_rib_entry = NULL;
        //print_route(p_route);
        HASH_FIND_STR(p_rt_states->ribs[asid], p_route->prefix, p_rib_entry);
        if (p_rib_entry) {
            rl_add_route(&p_rib_entry->rl, *tmp_asid, p_route, p_rt_states->as_policies[asid].selection_policy);
        } else {
            p_rib_entry = malloc(sizeof *p_rib_entry);
            if (!p_rib_entry) {
                printf("malloc error for p_rib_entry [%s]\n", __FUNCTION__);
                return MALLOC_ERROR;
            }
            p_rib_entry->key = my_strdup(p_route->prefix);
            p_rib_entry->augmented_reach = NULL;
            p_rib_entry->rl = NULL;
            rl_add_route(&p_rib_entry->rl, *tmp_asid, p_route, p_rt_states->as_policies[asid].selection_policy);
            HASH_ADD_KEYPTR(hh, p_rt_states->ribs[asid], p_rib_entry->key, strlen(p_rib_entry->key), p_rib_entry);
        }
    }

    return SUCCESS;
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
            rl_add_route(&p_rib_entry->rl, p_bgp_input_msg->asid, p_bgp_input_msg->p_route, p_rt_states->as_policies[i].selection_policy);
            p_new_rn[i] = rl_get_selected_route_node(p_rib_entry->rl);
            HASH_ADD_KEYPTR(hh, p_rt_states->ribs[i], p_rib_entry->key, strlen(p_rib_entry->key), p_rib_entry);
        } else {
            // get next hop asid before processing
            p_old_rn[i] = rl_get_selected_route_node(p_rib_entry->rl);
            // update route
            if (p_bgp_input_msg->oprt_type == ANNOUNCE) {
                rl_add_route(&p_rib_entry->rl, p_bgp_input_msg->asid, p_bgp_input_msg->p_route, p_rt_states->as_policies[i].selection_policy);
            } else if (p_bgp_input_msg->oprt_type == WITHDRAW) {
                rl_del_route(&p_rib_entry->rl, p_bgp_input_msg->asid, p_bgp_input_msg->p_route, p_rt_states->as_policies[i].selection_policy);
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
                reach_changed[i] = update_augmented_reach(&p_rib_entry->augmented_reach, p_rib_entry->rl, p_rt_states->sdn_orgnl_reach + i * p_rt_states->as_size);
                printf("reach_changed[%d]:%d [%s]\n", i, reach_changed[i], __FUNCTION__);
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
        (*pp_bgp_output_msgs)[j].nh_asid = p_bgp_input_msg->asid;
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

uint32_t process_sdn_reach(uint8_t *p_sdn_reach, const uint32_t *p_reach, uint32_t reach_size, uint8_t oprt_type)
{
    if (!p_sdn_reach || !p_reach) return SUCCESS;
    uint32_t i;
    uint8_t v = (oprt_type == ANNOUNCE) ? 1 : 0;

    for (i = 0; i < reach_size; i++) {
        printf("updated p_reach[%u]:%u,%u [%s]\n", i, p_reach[i], v, __FUNCTION__);
        p_sdn_reach[p_reach[i]] = v;
    }

    return SUCCESS;
}

uint32_t get_sdn_reach_by_prefix(const char *prefix, uint8_t *p_sdn_reach, uint32_t num, rib_map_t *p_rib, uint32_t **pp_ret_reach, uint32_t *p_ret_reach_size)
{
    if (!pp_ret_reach || *pp_ret_reach || !p_ret_reach_size|| !prefix) {
        return SUCCESS;
    }
    rib_map_t *p_rib_entry = NULL;
    route_node_t *p_tmp_rn = NULL;
    *p_ret_reach_size = 0;
    uint32_t i = 0;

    HASH_FIND_STR(p_rib, prefix, p_rib_entry);
    if (!p_rib_entry) return SUCCESS;

    p_tmp_rn = p_rib_entry->rl->head;
    while (p_tmp_rn) {
        if (p_sdn_reach[p_tmp_rn->advertiser_asid]) (*p_ret_reach_size)++;
        p_tmp_rn = p_tmp_rn->next;
    }
    *pp_ret_reach = malloc(*p_ret_reach_size * sizeof(**pp_ret_reach));
    p_tmp_rn = p_rib_entry->rl->head;
    while (p_tmp_rn) {
        if (p_sdn_reach[p_tmp_rn->advertiser_asid]) {
            (*pp_ret_reach)[i] = p_tmp_rn->advertiser_asid;
            i++;
        }
        p_tmp_rn = p_tmp_rn->next;
    }
    assert(i == *p_ret_reach_size);

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

uint32_t print_rs_rib_size(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i, count;

    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_tmp_rn = NULL;

    for (i = 0; i < num; i++) {
        count = 0;
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            p_tmp_rn = p_rib_entry->rl->head;
            while (p_tmp_rn) {
                count++;
                p_tmp_rn = p_tmp_rn->next;
            }
        }
        printf("as_id: %u, rib size: %u\n", i, count);
    }
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
                printf("advertiser_asid: %d, route: ", p_best_rn->advertiser_asid);
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
                    printf("[*] advertiser_asid:%d, route: ", p_tmp_rn->advertiser_asid);
                } else {
                    printf("    advertiser_asid:%d, route: ", p_tmp_rn->advertiser_asid);
                }
                print_route(p_tmp_rn->route);
                p_tmp_rn = p_tmp_rn->next;
            }
        }
    }
    return SUCCESS;
}
