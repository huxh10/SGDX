#ifndef _TIME_UTILS_H_
#define _TIME_UTILS_H_

#define _POSIX_C_SOURCE 200809L

void print_current_time_with_us(char *func);
uint64_t get_us_time();

#endif
