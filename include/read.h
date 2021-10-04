#ifndef READ_H
#define READ_H
#include "ptype.h"

FILE* fopen_at_path(char* pathname, char* filename, char* modes);
size_t get_ether_info(ether_header_t* ret, FILE* pcap);
size_t get_ip_info(ip_header_t* ret, FILE* pcap);
void get_packet_header (packet_header_t* ret, FILE* pcap);


#endif