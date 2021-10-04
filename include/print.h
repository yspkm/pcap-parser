#ifndef PRINT_H
#define PRINT_H

#include "ptype.h"

void print_bytes_file(FILE* file, int len);
void print_bits(u_int32_t u, int len);
void print_bytes(byte_t* info_check, int len);
void print_ip_addr(byte_t* ip_addr);
void print_mac_addr(byte_t* mac_addr);

#endif
