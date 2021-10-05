#ifndef READ_H
#define READ_H
#include "ptype.h"

#define FILE_HEADER_LEN 24

FILE *fopen_at_path(char *pathname, char *filename, char *modes);
void get_ether_info(ether_header_t *ret, FILE *pcap);
void get_ip_info(ip_header_t *ret, FILE *pcap);
void get_packet_header(packet_header_t *ret, FILE *pcap);

#endif