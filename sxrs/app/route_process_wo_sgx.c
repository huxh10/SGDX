#include <stdio.h>
#include <stdlib.h>
#include "app_types.h"
#include "shared_types.h"
#include "msg_handler.h"
#include "error_codes.h"
#include "bgp.h"
#include "rs.h"
#include "route_process_wo_sgx.h"

rt_state_t *gp_rt_states = NULL;
int g_verbose = 0;

void init_wo_sgx(as_cfg_t *p_as_cfg, int verbose)
{
    uint32_t i = 0;
    g_verbose = verbose;

    if (load_asmap(&gp_rt_states, p_as_cfg->as_size, p_as_cfg->as_id_2_n) == MALLOC_ERROR)  exit(-1);
    SAFE_FREE(p_as_cfg->as_id_2_n);
    fprintf(stderr, "load as id map done [%s]\n", __FUNCTION__);

    gp_rt_states->as_policies = p_as_cfg->as_policies;
    fprintf(stderr, "load as policies done [%s]\n", __FUNCTION__);

    if (!p_as_cfg->rib_file_dir) return;
    int dir_len = strlen(p_as_cfg->rib_file_dir);
    char rib_file[dir_len + 9];         // 9 is for rib name (8), such as rib_1000, and '\0' (1)
    memcpy(rib_file, p_as_cfg->rib_file_dir, dir_len);
    char *line = NULL;                  // buffer address
    size_t len = 0;                     // allocated buffer size
    route_t tmp_route = {NULL, NULL, NULL, NULL, {0, NULL}, NULL, 0, 0};
    uint32_t tmp_asid;
    FILE *fp;
    for (i = 0; i < p_as_cfg->as_size; i++) {
        sprintf(rib_file + dir_len, "rib_%d", i);
        if ((fp = fopen(rib_file, "r")) == NULL) {
            fprintf(stderr, "can not open file: %s [%s]\n", rib_file, __FUNCTION__);
            exit(-1);
        }
        while (getline(&line, &len, fp) != -1) {
            process_rib_file_line(i, line, &tmp_asid, &tmp_route, gp_rt_states);
        }
        fclose(fp);
    }
    SAFE_FREE(line);
    fprintf(stderr, "load rib from file done [%s]\n", __FUNCTION__);
}

void process_bgp_route_wo_sgx(bgp_route_input_dsrlz_msg_t *p_bgp_dsrlz_msg)
{
    bgp_route_output_dsrlz_msg_t *p_bgp_route_output_dsrlz_msgs = NULL;
    sdn_reach_output_dsrlz_msg_t *p_sdn_reach_output_dsrlz_msgs = NULL;
    size_t i, bgp_output_msg_num = 0, sdn_output_msg_num = 0, ret_msg_size = 0;

    asn_map_t *asmap_entry;
    HASH_FIND_INT(gp_rt_states->as_n_2_id, &p_bgp_dsrlz_msg->asn, asmap_entry);
    p_bgp_dsrlz_msg->asid = asmap_entry->as_id;

    if (process_non_transit_route(p_bgp_dsrlz_msg, gp_rt_states, &p_bgp_route_output_dsrlz_msgs, &bgp_output_msg_num, &p_sdn_reach_output_dsrlz_msgs, &sdn_output_msg_num) != SUCCESS) exit(-1);

    if (g_verbose == 4) print_rs_ribs(gp_rt_states->ribs, gp_rt_states->as_size);

    for (i = 0; i < bgp_output_msg_num; i++) {
        handle_bgp_route(&p_bgp_route_output_dsrlz_msgs[i]);
        free_bgp_route_output_dsrlz_msg(&p_bgp_route_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_bgp_route_output_dsrlz_msgs);
    for (i = 0; i < sdn_output_msg_num; i++) {
        handle_sdn_reach(p_sdn_reach_output_dsrlz_msgs[i].asid, p_sdn_reach_output_dsrlz_msgs[i].prefix, p_sdn_reach_output_dsrlz_msgs[i].reachability, p_sdn_reach_output_dsrlz_msgs[i].reach_size);
        free_sdn_reach_output_dsrlz_msg(&p_sdn_reach_output_dsrlz_msgs[i]);
    }
    SAFE_FREE(p_sdn_reach_output_dsrlz_msgs);

    return;
}

void process_sdn_reach_wo_sgx(uint32_t asid, const uint32_t *p_reach, uint32_t reach_size, uint8_t oprt_type)
{
    process_sdn_reach(gp_rt_states->sdn_orgnl_reach + asid * gp_rt_states->as_size, p_reach, reach_size, oprt_type);
}

void get_sdn_reach_by_prefix_wo_sgx(uint32_t asid, const char *prefix)
{
    uint32_t *p_sdn_reach = NULL;
    uint32_t reach_size = 0;

    get_sdn_reach_by_prefix(prefix, gp_rt_states->sdn_orgnl_reach + asid * gp_rt_states->as_size, gp_rt_states->as_size, gp_rt_states->ribs[asid], &p_sdn_reach, &reach_size);
    handle_sdn_reach(asid, prefix, p_sdn_reach, reach_size);
    SAFE_FREE(p_sdn_reach);
}
