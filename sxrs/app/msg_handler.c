#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jansson.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "server.h"
#include "bgp.h"
#include "app_types.h"
#include "msg_handler.h"
#include "epoll_utils.h"

#ifdef W_SGX
#include "route_process_w_sgx.h"
#else
#include "route_process_wo_sgx.h"
#endif

msg_state_t g_msg_states;
int g_crnt_route_id;
int g_first_sdn_reach_counter = 0;

void create_start_signal()
{
    FILE *fp;

    if ((fp = fopen(GEN_SIG_FILE, "w+")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", GEN_SIG_FILE, __FUNCTION__);
        exit(-1);
    }
    fclose(fp);
}

void msg_handler_init(as_cfg_t *p_as_cfg)
{
    int i;
    g_msg_states.pctrlr_sfds = malloc(p_as_cfg->as_size * sizeof *g_msg_states.pctrlr_sfds);
    if (!g_msg_states.pctrlr_sfds) {
        fprintf(stderr, "malloc error for g_msg_states.pctrlr_sfds [%s]\n", __FUNCTION__);
        exit(-1);
    }
    for (i = 0; i < p_as_cfg->as_size; i++) {
        g_msg_states.pctrlr_sfds[i] = -1;
    }
    g_msg_states.as_size = p_as_cfg->as_size;
    g_msg_states.as_ips = p_as_cfg->as_ips;
    g_msg_states.vnh_states.crnt_vnh = 2885681408;      // 172.0.1.0
    g_msg_states.vnh_states.vnh_map = NULL;
}

void handle_bgp_route(bgp_route_input_dsrlz_msg_t *p_bgp_msg, uint32_t *p_bgp_output_asids, size_t bgp_output_as_num)
{
    uint32_t i, j, k, msg_size, offset;
    char *route = NULL, *oprt_type = NULL;
    char *msg_to_as = NULL, *msg_to_pctrlr = NULL;
    char *neighbor_ip;

    // send msg to as
    // "neighbor "(9) + neighbor_ip + " announce route "(16) + prefix + " next-hop "(10) + next_hop + " as-path [ ( "(13) + asns+' ' + ") ]"(3)
    // "neighbor "(9) + neighbor_ip + " withdraw route "(16) + prefix + " next-hop "(10) + next_hop
    if (p_bgp_msg->oprt_type == ANNOUNCE) {
        oprt_type = "announce";
        msg_size = 51;  // 9+16+10+13+3
        msg_size += 11 * p_bgp_msg->p_route->as_path.length;  // allocate 10 bytes string for each asn in as_path, one more whitespace
    } else if (p_bgp_msg->oprt_type == WITHDRAW) {
        oprt_type = "withdraw";
        msg_size = 35;  // 9+16+10
    } else {
        return;
    }
    msg_size += strlen(p_bgp_msg->p_route->prefix);
    msg_size += strlen(p_bgp_msg->p_route->next_hop);
    msg_size += 1;  // '\0'

    for (k = 0; k < bgp_output_as_num; k++) {
        for (i = 0; i < g_msg_states.as_ips[p_bgp_output_asids[k]].ip_num; i++) {
            neighbor_ip = g_msg_states.as_ips[p_bgp_output_asids[k]].ips[i];
            msg_to_as = malloc(msg_size + strlen(neighbor_ip));
            // write to msg
            offset = 0;
            memcpy(msg_to_as + offset, "neighbor ", 9);
            offset += 9;
            memcpy(msg_to_as + offset, neighbor_ip, strlen(neighbor_ip));
            offset += strlen(neighbor_ip);
            msg_to_as[offset] = ' ';
            offset += 1;
            memcpy(msg_to_as + offset, oprt_type, 8);
            offset += 8;
            memcpy(msg_to_as + offset, " route ", 7);
            offset += 7;
            memcpy(msg_to_as + offset, p_bgp_msg->p_route->prefix, strlen(p_bgp_msg->p_route->prefix));
            offset += strlen(p_bgp_msg->p_route->prefix);
            memcpy(msg_to_as + offset, " next-hop ", 10);
            offset += 10;
            memcpy(msg_to_as + offset, p_bgp_msg->p_route->next_hop, strlen(p_bgp_msg->p_route->next_hop));
            offset += strlen(p_bgp_msg->p_route->next_hop);
            if (p_bgp_msg->p_route->oprt_type == ANNOUNCE) {
                memcpy(msg_to_as + offset, " as-path [ ( ", 13);
                offset += 13;
                for (j = 0; j < p_bgp_msg->p_route->as_path.length; j++) {
                    offset += sprintf(msg_to_as + offset, "%d ", p_bgp_msg->p_route->as_path.asns[j]);
                }
                memcpy(msg_to_as + offset, ") ]", 3);
                offset += 3;
            }
            msg_to_as[offset] = 0;
            // send to exabgp's client.py
            //fprintf(stdout, "prepare to send msg:%s to asid:%d router [%s]\n", msg_to_as, p_bgp_msg->asid, __FUNCTION__);
            send_msg_to_as(msg_to_as);
            SAFE_FREE(msg_to_as);
        }
    }
}

int handle_exabgp_msg(char *msg)
{
    uint32_t i;
    json_t *j_root, *j_stop, *j_route_id, *j_neighbor, *j_asn, *j_peer_id, *j_neighbor_ip, *j_state, *j_message, *j_update, *j_attr, *j_origin, *j_as_path, *j_as_path_elmnt, *j_med, *j_community, *j_atomic_aggregate, *j_oprt_type, *j_ipv4_uni, *j_prefixes, *j_prefix;
    json_error_t j_err;
    const char *key_next_hop, *key_prefix;
    bgp_route_input_dsrlz_msg_t bgp_dsrlz_msg;

    // message parsing
    j_root = json_loads(msg, 0, &j_err);
    if (!j_root) {
        fprintf(stderr, "error: on line %d:%s [%s]\n", j_err.line, j_err.text, __FUNCTION__);
        json_decref(j_root);
        return 0;
    }

    if (!json_is_object(j_root)) {
        fprintf(stderr, "fmt error: json object required [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }

    // should we exit?
    j_stop = json_object_get(j_root, "stop");
    if (json_is_integer(j_stop)) {
        json_decref(j_root);
        return -1;
    }

    // get route_id
    j_route_id = json_object_get(j_root, "route_id");
    if (!json_is_integer(j_route_id)) {
        fprintf(stderr, "fmt error: key [route_id] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }
    g_crnt_route_id = json_integer_value(j_route_id);

    // get asn
    j_neighbor = json_object_get(j_root, "neighbor");
    if (!json_is_object(j_neighbor)) {
        fprintf(stderr, "fmt error: key [neighbor] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }
    j_asn = json_object_get(j_neighbor, "asn");
    if (!json_is_object(j_asn)) {
        fprintf(stderr, "fmt error: key [neighbor][asn] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }
    j_peer_id = json_object_get(j_asn, "peer");
    if (!json_is_string(j_peer_id)) {
        fprintf(stderr, "fmt error: value [neighbor][asn][peer] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }
    bgp_dsrlz_msg.asn = atoi(json_string_value(j_peer_id));
    // get neighbor addr
    j_neighbor_ip = json_object_get(j_neighbor, "ip");
    if (!json_is_string(j_neighbor_ip)) {
        fprintf(stderr, "fmt error: value [neighbor][ip] is wrong [%s]\n", __FUNCTION__);
        json_decref(j_root);
        return 0;
    }

    // route assignment
    bgp_dsrlz_msg.p_route = malloc(sizeof *bgp_dsrlz_msg.p_route);
    init_route_ptr(bgp_dsrlz_msg.p_route);
    bgp_dsrlz_msg.p_route->neighbor = my_strdup(json_string_value(j_neighbor_ip));
    //fprintf(stdout, "neighbor ip: %s [%s]\n", json_string_value(j_neighbor_ip), __FUNCTION__);

    // peer is down
    j_state = json_object_get(j_neighbor, "state");
    if (json_is_string(j_state)) {
        fprintf(stdout, "peer %u is down [%s]\n", bgp_dsrlz_msg.asn, __FUNCTION__);
        // TODO handle msg[neighbor][state] == "down"
    }

    // get update message
    j_message = json_object_get(j_neighbor, "message");
    if (!json_is_object(j_message)) {
        fprintf(stderr, "fmt error: key [neighbor][message] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }
    j_update = json_object_get(j_message, "update");
    if (!json_is_object(j_update)) {
        fprintf(stdout, "no udpate messages [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }
    j_attr = json_object_get(j_update, "attribute");
    if (!json_is_object(j_attr)) {
        // TODO: withdraw announcement could have no attributes
        fprintf(stderr, "fmt error: key [neighbor][message][update][attribute] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }
    // origin
    j_origin = json_object_get(j_attr, "origin");
    bgp_dsrlz_msg.p_route->origin = json_is_string(j_origin) ? my_strdup(json_string_value(j_origin)) : "";
    // as-path
    j_as_path = json_object_get(j_attr, "as-path");
    if (!json_is_array(j_as_path) || json_array_size(j_as_path) == 0) {
        fprintf(stderr, "fmt error: [neighbor][message][update][attribute][as-path] is wrong [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }
    bgp_dsrlz_msg.p_route->as_path.length = json_array_size(j_as_path);
    bgp_dsrlz_msg.p_route->as_path.asns = malloc(bgp_dsrlz_msg.p_route->as_path.length * sizeof * bgp_dsrlz_msg.p_route->as_path.asns);
    //fprintf(stdout, "as_path: ");
    for (i = 0; i < json_array_size(j_as_path); i++) {
        j_as_path_elmnt = json_array_get(j_as_path, i);
        if (!json_is_integer(j_as_path_elmnt)) {
            fprintf(stderr, "fmt error: [neighbor][message][update][attribute][as-path][%d] is wrong [%s]\n", i, __FUNCTION__);
            free_route_ptr(&bgp_dsrlz_msg.p_route);
            json_decref(j_as_path_elmnt);
            return 0;
        }
        bgp_dsrlz_msg.p_route->as_path.asns[i] = json_integer_value(j_as_path_elmnt);
        //fprintf(stdout, "%d ", (int) json_integer_value(j_as_path_elmnt));
    }
    //fprintf(stdout, "[%s]\n", __FUNCTION__);
    // med
    j_med = json_object_get(j_attr, "med");
    bgp_dsrlz_msg.p_route->med = json_is_integer(j_med) ? json_integer_value(j_med) : 0;
    // community
    // TODO: check the key is community or communities
    j_community = json_object_get(j_attr, "community");
    bgp_dsrlz_msg.p_route->communities = json_is_string(j_community) ? my_strdup(json_string_value(j_community)) : my_strdup("");
    // atomic-aggregate
    j_atomic_aggregate = json_object_get(j_attr, "atomic-aggregate");
    bgp_dsrlz_msg.p_route->atomic_aggregate = json_is_integer(j_atomic_aggregate) ? json_integer_value(j_atomic_aggregate) : 0;
    // oprt_type
    bgp_dsrlz_msg.oprt_type = -1;
    j_oprt_type = json_object_get(j_update, "announce");
    if (json_is_object(j_oprt_type)) {
        bgp_dsrlz_msg.oprt_type = ANNOUNCE;
    } else {
        j_oprt_type = json_object_get(j_update, "withdraw");
        if (json_is_object(j_oprt_type)) {
            bgp_dsrlz_msg.oprt_type = WITHDRAW;
        }
    }
    if (bgp_dsrlz_msg.oprt_type == -1) {
        fprintf(stderr, "key [neighbor][message][update][oprt_type] is wrong  [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }
    j_ipv4_uni = json_object_get(j_oprt_type, "ipv4 unicast");
    if (!json_is_object(j_ipv4_uni)) {
        fprintf(stderr, "no ipv4 unicast type prefix [%s]\n", __FUNCTION__);
        free_route_ptr(&bgp_dsrlz_msg.p_route);
        json_decref(j_root);
        return 0;
    }

    // get next_hop and prefix, then process each msg
    if (bgp_dsrlz_msg.oprt_type == ANNOUNCE) {
        json_object_foreach(j_ipv4_uni, key_next_hop, j_prefixes) {
            if (!json_is_object(j_prefixes)) continue;
            bgp_dsrlz_msg.p_route->next_hop = my_strdup(key_next_hop);
            json_object_foreach(j_prefixes, key_prefix, j_prefix) {
                bgp_dsrlz_msg.p_route->prefix = my_strdup(key_prefix);
                //fprintf(stdout, "route prefix:%s next_hop:%s [%s]\n", key_prefix, key_next_hop, __FUNCTION__);
                // process msg
#ifdef W_SGX
                process_bgp_route_w_sgx(&bgp_dsrlz_msg);
#else
                process_bgp_route_wo_sgx(&bgp_dsrlz_msg);
#endif
                SAFE_FREE(bgp_dsrlz_msg.p_route->prefix);
            }
            SAFE_FREE(bgp_dsrlz_msg.p_route->next_hop);
        }
    } else if (bgp_dsrlz_msg.oprt_type == WITHDRAW) {
        json_object_foreach(j_ipv4_uni, key_prefix, j_prefix) {
            bgp_dsrlz_msg.p_route->prefix = my_strdup(key_prefix);
            // process msg
#ifdef W_SGX
            process_bgp_route_w_sgx(&bgp_dsrlz_msg);
#else
            process_bgp_route_wo_sgx(&bgp_dsrlz_msg);
#endif
            SAFE_FREE(bgp_dsrlz_msg.p_route->prefix);
        }
    }

    free_route_ptr(&bgp_dsrlz_msg.p_route);
    json_decref(j_root);
    return g_crnt_route_id;
}
