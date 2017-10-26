#ifndef __RS_H__
#define __RS_H__

uint32_t load_asmap(rt_state_t **pp_rt_states, uint32_t as_size, uint32_t *as_id_2_n);

uint32_t filter_route(rt_state_t *p_rt_states, uint32_t asn, uint32_t **pp_bgp_output_asids, size_t *p_bgp_output_as_num);

#endif
