#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jansson.h>
#include "server.h"
#include "bgp.h"
#include "app_types.h"
#include "msg_handler.h"

#ifdef W_SGX
#include "route_process_w_sgx.h"
#else
#include "route_process_wo_sgx.h"
#endif

void handle_resp_set(uint32_t asn, const char *prefix, const uint32_t *p_resp_set, uint32_t resp_set_size)
{
    char *s_resp_set = NULL;
    uint32_t i;
    json_t *j_root = json_object();
    json_t *j_msg = json_object();
    json_t *j_resp_set = json_array();

    for (i = 0; i < resp_set_size; i++) {
        json_array_append(j_resp_set, json_integer(p_resp_set[i]));
    }
    json_object_set(j_msg, prefix, j_resp_set);
    json_decref(j_resp_set);
    json_object_set(j_root, "set", j_msg);
    json_decref(j_msg);

    s_resp_set = json_dumps(j_root, 0);
    send_ss_msg_to_pctrlr((const char *) s_resp_set, asn);
    SAFE_FREE(s_resp_set);
    json_decref(j_root);
}

void handle_resp_route(resp_dec_msg_t *p_resp_dec_msg)
{
    uint32_t i;
    char *route = NULL, *oprt_type = NULL;
    if (p_resp_dec_msg->oprt_type == ANNOUNCE) {
        oprt_type = "announce";
    } else if (p_resp_dec_msg->oprt_type == WITHDRAW) {
        oprt_type = "withdraw";
    } else {
        return;
    }
    json_t *j_root = json_object();
    json_t *j_msg = json_object();
    json_t *j_as_path = json_array();

    json_object_set_new(j_msg, "asn", json_integer(p_resp_dec_msg->asn));
    json_object_set_new(j_msg, "oprt-type", json_string(oprt_type));
    json_object_set_new(j_msg, "prefix", json_string(p_resp_dec_msg->prefix));
    json_object_set_new(j_msg, "next-hop", json_string(p_resp_dec_msg->next_hop));
    for (i = 0; i < p_resp_dec_msg->as_path.length; i++) {
        json_array_append(j_as_path, json_integer(p_resp_dec_msg->as_path.asns[i]));
    }
    json_object_set(j_msg, "as-path", j_as_path);
    json_decref(j_as_path);

    json_object_set(j_root, "bgp", j_msg);
    json_decref(j_msg);

    route = json_dumps(j_root, 0);
    send_bgp_msg_to_pctrlr((const char *) route, p_resp_dec_msg->asn);
    SAFE_FREE(route);
    json_decref(j_root);
}

void handle_bgp_msg(char *msg)
{
    uint32_t i;
    json_t *j_root, *j_neighbor, *j_asn, *j_peer_id, *j_neighbor_ip, *j_state, *j_message, *j_update, *j_attr, *j_origin, *j_as_path, *j_as_path_elmnt, *j_med, *j_community, *j_atomic_aggregate, *j_oprt_type, *j_ipv4_uni, *j_prefixes, *j_prefix;
    json_error_t j_err;
    const char *key_next_hop, *key_prefix;
    bgp_dec_msg_t bgp_dec_msg;

    // message parsing
    j_root = json_loads(msg, 0, &j_err);
    if (!j_root) {
        fprintf(stderr, "error: on line %d:%s [%s]\n", j_err.line, j_err.text, __FUNCTION__);
        json_decref(j_root);
        return;
    }

    if (!json_is_object(j_root)) {
        fprintf(stderr, "fmt error: json object required [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }

    // get as id, currently use asn as consecutive id
    j_neighbor = json_object_get(j_root, "neighbor");
    if (!json_is_object(j_neighbor)) {
        fprintf(stderr, "fmt error: key [neighbor] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }
    j_asn = json_object_get(j_neighbor, "asn");
    if (!json_is_object(j_asn)) {
        fprintf(stderr, "fmt error: key [neighbor][asn] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }
    j_peer_id = json_object_get(j_asn, "peer");
    if (!json_is_string(j_peer_id)) {
        fprintf(stderr, "fmt error: value [neighbor][asn][peer] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }
    bgp_dec_msg.asn = atoi(json_string_value(j_peer_id));
    // get neighbor addr
    j_neighbor_ip = json_object_get(j_neighbor, "ip");
    if (!json_is_string(j_neighbor_ip)) {
        fprintf(stderr, "fmt error: value [neighbor][ip] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }

    // route assignment
    bgp_dec_msg.p_route = malloc(sizeof *bgp_dec_msg.p_route);
    bgp_dec_msg.p_route->neighbor = my_strdup(json_string_value(j_neighbor_ip));

    // peer is down
    j_state = json_object_get(j_neighbor, "state");
    if (json_is_string(j_state)) {
        fprintf(stdout, "peer %u is down [%s]\n", bgp_dec_msg.asn, __FUNCTION__);
        // TODO hanlde msg[neighbor][state] == "down"
    }

    // get update message
    j_message = json_object_get(j_neighbor, "message");
    if (!json_is_object(j_message)) {
        fprintf(stderr, "fmt error: key [neighbor][message] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }
    j_update = json_object_get(j_message, "update");
    if (!json_is_object(j_update)) {
        fprintf(stdout, "no udpate messages [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }
    j_attr = json_object_get(j_update, "attribute");
    if (!json_is_object(j_attr)) {
        fprintf(stderr, "fmt error: key [neighbor][message][update][attribute] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }
    // origin
    j_origin = json_object_get(j_attr, "origin");
    bgp_dec_msg.p_route->origin = json_is_string(j_origin) ? my_strdup(json_string_value(j_origin)) : "";
    // as-path
    j_as_path = json_object_get(j_attr, "as-path");
    if (!json_is_array(j_as_path) || json_array_size(j_as_path) == 0) {
        fprintf(stderr, "fmt error: [neighbor][message][update][attribute][as-path] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }
    bgp_dec_msg.p_route->as_path.length = json_array_size(j_as_path);
    bgp_dec_msg.p_route->as_path.asns = malloc(bgp_dec_msg.p_route->as_path.length * sizeof * bgp_dec_msg.p_route->as_path.asns);
    for (i = 0; i < json_array_size(j_as_path); i++) {
        j_as_path_elmnt = json_array_get(j_as_path, i);
        if (!json_is_integer(j_as_path_elmnt)) {
            fprintf(stderr, "fmt error: [neighbor][message][update][attribute][as-path][%d] is wrong [%s]\n", i, __FUNCTION__);
            free_route_ptr(&bgp_dec_msg.p_route);
            json_decref(j_as_path_elmnt);
            return;
        }
        bgp_dec_msg.p_route->as_path.asns[i] = json_integer_value(j_as_path_elmnt);
    }
    // med
    j_med = json_object_get(j_attr, "med");
    bgp_dec_msg.p_route->med = json_is_integer(j_med) ? json_integer_value(j_med) : 0;
    // community
    // TODO: check the key is community or communities
    j_community = json_object_get(j_attr, "community");
    bgp_dec_msg.p_route->communities = json_is_string(j_community) ? my_strdup(json_string_value(j_community)) : "";
    // atomic-aggregate
    j_atomic_aggregate = json_object_get(j_attr, "atomic-aggregate");
    bgp_dec_msg.p_route->atomic_aggregate = json_is_integer(j_atomic_aggregate) ? json_integer_value(j_atomic_aggregate) : 0;
    // oprt_type
    bgp_dec_msg.oprt_type = -1;
    j_oprt_type = json_object_get(j_update, "announce");
    if (json_is_object(j_oprt_type)) {
        bgp_dec_msg.oprt_type = ANNOUNCE;
    }
    j_oprt_type = json_object_get(j_update, "withdraw");
    if (json_is_object(j_oprt_type)) {
        bgp_dec_msg.oprt_type = WITHDRAW;
    }
    if (bgp_dec_msg.oprt_type == -1) {
        fprintf(stderr, "key [neighbor][message][update][oprt_type] is wrong  [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }
    j_ipv4_uni = json_object_get(j_oprt_type, "ipv4 unicast");
    if (!json_is_object(j_ipv4_uni)) {
        fprintf(stderr, "no ipv4 unicast type prefix [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dec_msg.p_route);
        json_decref(j_root);
        return;
    }

    // get next_hop and prefix, then process each msg
    if (bgp_dec_msg.oprt_type == ANNOUNCE) {
        json_object_foreach(j_ipv4_uni, key_next_hop, j_prefixes) {
            if (!json_is_object(j_prefixes)) continue;
            bgp_dec_msg.p_route->next_hop = my_strdup(key_next_hop);
            json_object_foreach(j_ipv4_uni, key_prefix, j_prefix) {
                bgp_dec_msg.p_route->prefix = my_strdup(key_prefix);
                // process msg
#ifdef W_SGX
                route_process_w_sgx_run(&bgp_dec_msg);
#else
                route_process_wo_sgx_run(&bgp_dec_msg);
#endif
                SAFE_FREE(bgp_dec_msg.p_route->prefix);
            }
            SAFE_FREE(bgp_dec_msg.p_route->next_hop);
        }
    } else if (bgp_dec_msg.oprt_type == WITHDRAW) {
        json_object_foreach(j_ipv4_uni, key_prefix, j_prefix) {
            bgp_dec_msg.p_route->prefix = my_strdup(key_prefix);
            // process msg
#ifdef W_SGX
            route_process_w_sgx_run(&bgp_dec_msg);
#else
            route_process_wo_sgx_run(&bgp_dec_msg);
#endif
            SAFE_FREE(bgp_dec_msg.p_route->prefix);
        }
    }

    free_route_ptr(&bgp_dec_msg.p_route);
    json_decref(j_root);
    return;
}

void handle_pctrlr_msg(char *msg, int src_sfd, uint32_t *p_src_id, int *pctrlr_bgp_sfds, int *pctrlr_ss_sfds, int as_num)
{
    json_t *j_root, *j_msg_type, *j_asn, *j_con_type, *j_announcement, *j_add_parts, *j_del_parts, *j_part_elmnt, *j_prefix;
    json_error_t j_err;
    const char *msg_type, *con_type, *announcement, *prefix;
    uint32_t asn, *p_parts, i;

    // message parsing
    j_root = json_loads(msg, 0, &j_err);
    if (!j_root) {
        fprintf(stderr, "error: on line %d:%s [%s]\n", j_err.line, j_err.text, __FUNCTION__);
        json_decref(j_root);
        return;
    }

    if (!json_is_object(j_root)) {
        fprintf(stderr, "fmt error: json object required [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }

    // msgType
    j_msg_type = json_object_get(j_root, "msgType");
    if (!json_is_string(j_msg_type)) {
        fprintf(stderr, "fmt error: msg[msgType] is not string [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return;
    }
    msg_type = json_string_value(j_msg_type);
    if (!strcmp(msg_type, "hello")) {
        j_asn = json_object_get(j_root, "id");
        if (!json_is_integer(j_asn)) {
            fprintf(stderr, "fmt error: msg[id] is not integer [%s]\n", __FUNCTION__);
            json_decref(j_root);
            return;
        }
        asn = json_integer_value(j_asn);
        assert(asn < as_num && asn >= 0);
        assert(*p_src_id == -1);
        *p_src_id = asn;
        j_con_type = json_object_get(j_root, "conType");
        if (!json_is_string(j_con_type)) {
            fprintf(stderr, "fmt error: msg[conType] is not string [%s]\n", __FUNCTION__);
            // TODO figure out json_decref
            json_decref(j_root);
            return;
        }
        con_type = json_string_value(j_con_type);
        if (!strcmp(con_type, "bgp")) {
            pctrlr_bgp_sfds[asn] = src_sfd;
        } else if (!strcmp(con_type, "ss")) {
            pctrlr_ss_sfds[asn] = src_sfd;
        } else {
            fprintf(stderr, "fmt error: msg[conType] should be bgp or ss [%s]\n", __FUNCTION__);
            json_decref(j_root);
            return;
        }
    } else if (!strcmp(msg_type, "route")) {
        j_announcement = json_object_get(j_root, "announcement");
        if (!json_is_string(j_announcement)) {
            fprintf(stderr, "fmt error: msg[announcement] is not string [%s]\n", __FUNCTION__);
            json_decref(j_announcement);
            return;
        }
        announcement = json_string_value(j_announcement);
        send_msg_to_as(announcement);
    } else if (!strcmp(msg_type, "participant")) {
        j_add_parts = json_object_get(j_root, "add");
        if (json_is_array(j_add_parts)) {
            p_parts = malloc(json_array_size(j_add_parts) * sizeof *p_parts);
            for (i = 0; i < json_array_size(j_add_parts); i++) {
                j_part_elmnt = json_array_get(j_add_parts, i);
                if (!json_is_integer(j_part_elmnt)) {
                    fprintf(stderr, "fmt error: msg[add][%d] is not integer [%s]\n", i, __FUNCTION__);
                    json_decref(j_add_parts);
                    SAFE_FREE(p_parts);
                }
                // process msg
#ifdef W_SGX
                process_wo_sgx_update_active_parts(*p_src_id, (const uint32_t*) p_parts, json_array_size(j_add_parts), ANNOUNCE);
#else
                process_w_sgx_update_active_parts(*p_src_id, (const uint32_t *) p_parts, json_array_size(j_add_parts), ANNOUNCE);
#endif
                p_parts[i] = json_integer_value(j_part_elmnt);
            }
            SAFE_FREE(p_parts);
        }
        j_del_parts = json_object_get(j_root, "del");
        if (json_is_array(j_del_parts)) {
            p_parts = malloc(json_array_size(j_del_parts) * sizeof *p_parts);
            for (i = 0; i < json_array_size(j_del_parts); i++) {
                j_part_elmnt = json_array_get(j_del_parts, i);
                if (!json_is_integer(j_part_elmnt)) {
                    fprintf(stderr, "fmt error: msg[add][%d] is not integer [%s]\n", i, __FUNCTION__);
                    json_decref(j_del_parts);
                    SAFE_FREE(p_parts);
                }
                // process msg
#ifdef W_SGX
                process_wo_sgx_update_active_parts(*p_src_id, (const uint32_t*) p_parts, json_array_size(j_add_parts), WITHDRAW);
#else
                process_w_sgx_update_active_parts(*p_src_id, (const uint32_t *) p_parts, json_array_size(j_add_parts), WITHDRAW);
#endif
                p_parts[i] = json_integer_value(j_part_elmnt);
            }
            SAFE_FREE(p_parts);
        }
    } else if (!strcmp(msg_type, "set")) {
        j_prefix = json_object_get(j_root, "prefix");
        if (!json_is_string(j_prefix)) {
            fprintf(stderr, "fmt error: msg[prefix] is not string [%s]\n", __FUNCTION__);
            json_decref(j_root);
            return;
        }
        prefix = json_string_value(j_prefix);
        // process msg
#ifdef W_SGX
        process_wo_sgx_get_prefix_set(*p_src_id, prefix);
#else
        process_w_sgx_get_prefix_set(*p_src_id, prefix);
#endif
    }

    json_decref(j_root);
    return;
}
