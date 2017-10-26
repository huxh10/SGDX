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
}

void process_bgp_route_wo_sgx(bgp_route_input_dsrlz_msg_t *p_bgp_dsrlz_msg)
{
    uint32_t *p_bgp_output_asids = NULL;
    size_t bgp_output_as_num = 0;

    if (filter_route(gp_rt_states, &p_bgp_output_asids, &bgp_output_as_num) != SUCCESS) exit(-1);
    handle_bgp_route(p_bgp_dsrlz_msg, p_bgp_output_asids, bgp_output_as_num);
    return;
}
