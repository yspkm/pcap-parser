#ifndef PRINT_H
#define PRINT_H

#include "ptype.h"
#include <time.h>

typedef enum _flag_e {
	DF,
	MF,
	EF // it means end of frag
} flag_t;

// print bytes from FILE*
void print_bytes_file(FILE* file, int len);
// print bytes from bytes array
void print_bytes(byte_t* info_check, int len);
// print bits
void print_bits(u_int32_t u, int len);

//hh:mm:ss.xxxxxx
void print_local_time(packet_header_t* pkthdr);
//e.g. 1.1.1.1
void print_ip_addr(byte_t* ip_addr);
//e.g. aa:aa:aa:aa:aa:aa
void print_mac_addr(byte_t* mac_addr);

//in decimal  
u_int32_t get_ttl(ip_header_t* iphdr);
// in flag_t format
flag_t get_ip_flag(ip_header_t* iphdr);
// convert big endian to little endian
u_int32_t hword_to_numeric(hword_t hword);
// in decimal 
u_int32_t get_offset(ip_header_t* iphdr);

void print_line(int num, char a);

#endif
