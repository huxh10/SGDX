#ifndef __RS_H__
#define __RS_H__

uint32_t load_asmap(rt_state_t **pp_rt_states, uint32_t as_size, uint32_t *as_id_2_n);

uint32_t process_rib_file_line(uint32_t asid, char *line, uint32_t *tmp_asid, route_t *p_route, rt_state_t *p_rt_states);

uint32_t process_non_transit_route(const bgp_route_input_dsrlz_msg_t *p_bgp_input_msg, rt_state_t *p_rt_states, bgp_route_output_dsrlz_msg_t **pp_bgp_output_msgs, size_t *p_bgp_output_msg_num, sdn_reach_output_dsrlz_msg_t **pp_sdn_output_msgs, size_t *p_sdn_output_msg_num);

uint32_t process_sdn_reach(uint8_t *p_sdn_reach, const uint32_t *p_reach, uint32_t reach_size, uint8_t oprt_type, uint32_t asid, rib_map_t *p_rib, bgp_route_output_dsrlz_msg_t **pp_bgp_output_msgs, size_t *p_bgp_output_msg_num, sdn_reach_output_dsrlz_msg_t **pp_sdn_output_msgs, size_t *p_sdn_output_msg_num);

uint32_t get_sdn_reach_by_prefix(const char *prefix, uint8_t *p_sdn_reach, uint32_t num, rib_map_t *p_rib, uint32_t **pp_ret_reach, uint32_t *p_ret_reach_size);

uint32_t print_rs_rib_size(rib_map_t **pp_ribs, uint32_t num);

uint32_t get_rs_ribs_num(rib_map_t **pp_ribs, uint32_t num);

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num);

#endif
