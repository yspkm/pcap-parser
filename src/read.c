#include "../include/read.h"

FILE* fopen_at_path(char* pathname, char* filename, char* modes)
{
	FILE* ret = NULL;
	int tot_len = strlen(pathname) + strlen(filename); // with '\0'
	char* fname = (char*) malloc(tot_len * sizeof(char));
	strcat(fname, pathname);
	strcat(fname, filename);
	ret = fopen(fname, modes);
	free(fname);
	return ret;
}

size_t get_ether_info(ether_header_t* ret, FILE* pcap)
{
	fread(ret, sizeof(ether_header_t), 1, pcap);
	return sizeof(ether_header_t);
}

size_t get_ip_info(ip_header_t* ret, FILE* pcap)
{
	fread(ret, sizeof(ip_header_t), 1, pcap);
	return sizeof(ip_header_t);
}

void get_packet_header (packet_header_t* ret, FILE* pcap)
{
	fread(ret, sizeof(packet_header_t), 1, pcap);
}
