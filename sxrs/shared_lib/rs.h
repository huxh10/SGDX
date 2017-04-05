#ifndef __RS_H__
#define __RS_H__

uint32_t compute_route_by_msg_queue(const bgp_dec_msg_t *p_bgp_msg, as_policy_t *p_policies, rib_map_t **pp_ribs, uint32_t num, resp_dec_msg_t **pp_resp_dec_msgs, size_t *p_resp_msg_num, resp_dec_set_msg_t **pp_resp_dec_set_msgs, size_t *p_resp_set_msg_num);

uint32_t update_active_parts(uint8_t *p_active_parts, const uint32_t *p_parts, uint32_t part_num, uint8_t oprt_type);

uint32_t get_prefix_set(const char *prefix, uint8_t *p_active_parts, uint32_t num, rib_map_t *p_rib, uint32_t **pp_resp_set, uint32_t *p_resp_set_size);

uint32_t get_rs_ribs_num(rib_map_t **pp_ribs, uint32_t num);

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num);

#endif
