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

void handle_sdn_reach(uint32_t asid, const char *prefix, const uint32_t *p_sdn_reach, uint32_t reach_size)
{
    uint32_t i;
    json_t *j_root = json_object();
    json_t *j_msg = json_object();
    json_t *j_sdn_reach = json_array();
    char *s_sdn_reach = NULL;

    for (i = 0; i < reach_size; i++) {
        json_array_append(j_sdn_reach, json_integer(p_sdn_reach[i]));
    }
    json_object_set(j_msg, prefix, j_sdn_reach);
    json_decref(j_sdn_reach);
    json_object_set(j_root, "sdn-reach", j_msg);
    json_decref(j_msg);
    if (g_crnt_route_id != -1) {
        json_object_set_new(j_root, "route_id", json_integer(g_crnt_route_id));
    }

    s_sdn_reach = json_dumps(j_root, 0);
    //fprintf(stdout, "prepare to send s_sdn_reach:%s to asid:%d pctrlr [%s]\n", s_sdn_reach, asid, __FUNCTION__);
    send_msg_to_pctrlr((const char *) s_sdn_reach, g_msg_states.pctrlr_sfds[asid]);
    SAFE_FREE(s_sdn_reach);
    json_decref(j_root);
}

void handle_bgp_route(bgp_route_output_dsrlz_msg_t *p_bgp_msg)
{
    uint32_t i, j, msg_size, offset;
    char *route = NULL, *oprt_type = NULL;
    char *msg_to_as = NULL, *msg_to_pctrlr = NULL;
    char *neighbor_ip;
    char *next_hop;
    // SDX virtual next hop related
    vnh_map_t *vnh_entry;
    struct in_addr ip_addr;

    // send msg to as
    // "neighbor "(9) + neighbor_ip + " announce route "(16) + prefix + " next-hop "(10) + next_hop + " as-path [ ( "(13) + asns+' ' + ") ]"(3)
    // "neighbor "(9) + neighbor_ip + " withdraw route "(16) + prefix + " next-hop "(10) + next_hop
    if (p_bgp_msg->oprt_type == ANNOUNCE) {
        oprt_type = "announce";
        msg_size = 51;  // 9+16+10+13+3
        msg_size += 11 * p_bgp_msg->as_path.length;  // allocate 10 bytes string for each asn in as_path, one more whitespace
    } else if (p_bgp_msg->oprt_type == WITHDRAW) {
        oprt_type = "withdraw";
        msg_size = 35;  // 9+16+10
    } else {
        return;
    }
    msg_size += strlen(p_bgp_msg->prefix);

    if (ENABLE_SDX) {
        HASH_FIND_STR(g_msg_states.vnh_states.vnh_map, p_bgp_msg->prefix, vnh_entry);
        if (vnh_entry) {
            next_hop = vnh_entry->vnh;
        } else {
            // new vnh assignment
            vnh_entry = malloc(sizeof *vnh_entry);
            g_msg_states.vnh_states.crnt_vnh++;
            ip_addr.s_addr = htonl(g_msg_states.vnh_states.crnt_vnh);
            next_hop = strdup(inet_ntoa(ip_addr));
            vnh_entry->prefix = strdup(p_bgp_msg->prefix);
            vnh_entry->vnh = next_hop;
            HASH_ADD_KEYPTR(hh, g_msg_states.vnh_states.vnh_map, vnh_entry->prefix, strlen(vnh_entry->prefix), vnh_entry);
        }
    } else {
        next_hop = p_bgp_msg->next_hop;
    }
    msg_size += strlen(next_hop);
    msg_size += 1;  // '\0'

    for (i = 0; i < g_msg_states.as_ips[p_bgp_msg->asid].ip_num; i++) {
        neighbor_ip = g_msg_states.as_ips[p_bgp_msg->asid].ips[i];
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
        memcpy(msg_to_as + offset, p_bgp_msg->prefix, strlen(p_bgp_msg->prefix));
        offset += strlen(p_bgp_msg->prefix);
        memcpy(msg_to_as + offset, " next-hop ", 10);
        offset += 10;
        memcpy(msg_to_as + offset, next_hop, strlen(next_hop));
        offset += strlen(next_hop);
        if (p_bgp_msg->oprt_type == ANNOUNCE) {
            memcpy(msg_to_as + offset, " as-path [ ( ", 13);
            offset += 13;
            for (j = 0; j < p_bgp_msg->as_path.length; j++) {
                offset += sprintf(msg_to_as + offset, "%d ", p_bgp_msg->as_path.asns[j]);
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

    if (!ENABLE_SDX) return;
    // send msg to pctrlr
    json_t *j_root = json_object();
    json_t *j_msg = json_object();

    json_object_set_new(j_msg, "oprt-type", json_string(oprt_type));
    json_object_set_new(j_msg, "prefix", json_string(p_bgp_msg->prefix));
    json_object_set_new(j_msg, "vnh", json_string(next_hop));
    json_object_set_new(j_msg, "nh-asid", json_integer(p_bgp_msg->nh_asid));

    json_object_set(j_root, "bgp-nh", j_msg);
    json_decref(j_msg);
    if (g_crnt_route_id != -1) {
        json_object_set_new(j_root, "route_id", json_integer(g_crnt_route_id));
    }

    msg_to_pctrlr = json_dumps(j_root, 0);
    //fprintf(stdout, "prepare to send msg:%s to asid:%d pctrlr [%s]\n", msg_to_pctrlr, p_bgp_msg->asid, __FUNCTION__);
    send_msg_to_pctrlr(msg_to_pctrlr, g_msg_states.pctrlr_sfds[p_bgp_msg->asid]);
    SAFE_FREE(msg_to_pctrlr);
    json_decref(j_root);
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
        // FIXME: brute force exiting
        if (ENABLE_SDX) {
            for (i = 0; i < g_msg_states.as_size; i++) {
                send_msg_to_pctrlr("stop", g_msg_states.pctrlr_sfds[i]);
                close(g_msg_states.pctrlr_sfds[i]);
            }
        }
        exit(0);
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

void handle_pctrlr_msg(char *msg, int src_sfd, uint32_t *p_con_id)
{
    json_t *j_root, *j_msg_type, *j_asid, *j_con_type, *j_announcement, *j_reach, *j_reach_elmnt, *j_prefix;
    json_error_t j_err;
    const char *msg_type, *con_type, *announcement, *prefix;
    uint32_t asid, *p_reach, i;
    g_crnt_route_id = -1;

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
    fprintf(stdout, "handle_pctrlr_msg, msgType:%s [%s]\n", msg_type, __FUNCTION__);

    // hello message set connection id using asid
    if (!strcmp(msg_type, "hello")) {
        j_asid = json_object_get(j_root, "id");
        if (!json_is_integer(j_asid)) {
            fprintf(stderr, "fmt error: msg[id] is not integer [%s]\n", __FUNCTION__);
            json_decref(j_root);
            return;
        }
        asid = json_integer_value(j_asid);
        assert(asid < g_msg_states.as_size && asid >= 0);
        assert(*p_con_id == -1);
        *p_con_id = asid;
        g_msg_states.pctrlr_sfds[asid] = src_sfd;
    } else if (!strcmp(msg_type, "sdn-reach")) {
        j_reach = json_object_get(j_root, "add");
        if (json_is_array(j_reach)) {
            p_reach = malloc(json_array_size(j_reach) * sizeof *p_reach);
            if (!p_reach) {
                fprintf(stderr, "malloc for sdn-reach add p_reach [%s]\n", __FUNCTION__);
                json_decref(j_root);
                return;
            }
            for (i = 0; i < json_array_size(j_reach); i++) {
                j_reach_elmnt = json_array_get(j_reach, i);
                if (!json_is_integer(j_reach_elmnt)) {
                    fprintf(stderr, "fmt error: msg[add][%d] is not integer [%s]\n", i, __FUNCTION__);
                    json_decref(j_reach);
                    SAFE_FREE(p_reach);
                }
                p_reach[i] = json_integer_value(j_reach_elmnt);
            }
            // process msg
#ifdef W_SGX
            process_sdn_reach_w_sgx(*p_con_id, p_reach, json_array_size(j_reach), ANNOUNCE);
#else
            process_sdn_reach_wo_sgx(*p_con_id, p_reach, json_array_size(j_reach), ANNOUNCE);
#endif
            SAFE_FREE(p_reach);
        }
        j_reach = json_object_get(j_root, "del");
        if (json_is_array(j_reach)) {
            p_reach = malloc(json_array_size(j_reach) * sizeof *p_reach);
            if (!p_reach) {
                fprintf(stderr, "malloc for sdn-reach del p_reach [%s]\n", __FUNCTION__);
                json_decref(j_root);
                return;
            }
            for (i = 0; i < json_array_size(j_reach); i++) {
                j_reach_elmnt = json_array_get(j_reach, i);
                if (!json_is_integer(j_reach_elmnt)) {
                    fprintf(stderr, "fmt error: msg[add][%d] is not integer [%s]\n", i, __FUNCTION__);
                    json_decref(j_reach);
                    SAFE_FREE(p_reach);
                }
                p_reach[i] = json_integer_value(j_reach_elmnt);
            }
            // process msg
#ifdef W_SGX
            process_sdn_reach_w_sgx(*p_con_id, p_reach, json_array_size(j_reach), WITHDRAW);
#else
            process_sdn_reach_wo_sgx(*p_con_id, p_reach, json_array_size(j_reach), WITHDRAW);
#endif
            SAFE_FREE(p_reach);
        }
        j_prefix = json_object_get(j_root, "get");
        if (json_is_string(j_prefix)) {
            prefix = json_string_value(j_prefix);
            // process msg
#ifdef W_SGX
            get_sdn_reach_by_prefix_w_sgx(*p_con_id, prefix);
#else
            get_sdn_reach_by_prefix_wo_sgx(*p_con_id, prefix);
#endif
        }
        if (g_first_sdn_reach_counter < g_msg_states.as_size) {
            g_first_sdn_reach_counter++;
            create_start_signal();
        }
    }

    json_decref(j_root);
    return;
}
