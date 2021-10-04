#include "../include/main.h"

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

void get_ether_info(ether_header_t* ret, FILE* pcap)
{
	fread(ret, sizeof(ether_header_t), 1, pcap);
}

u_int32_t

void print_ip_addr(byte_t* ip_addr)
{
	for (int i = 0;i < 4; i++)
	{
		printf("%d", ip_addr[i]);
		if (i !=3 ) {
			printf(".");
		} else {
			printf("\n");
		}
	}
}

void print_mac_addr(byte_t* mac_addr)
{
	for (int i = 0;i < 6; i++)
	{
		printf("%.2x", mac_addr[i]);
		if (i!=5){
			printf(":");
		} else {
			printf("\n");
		}
	}
}

void get_ip_info(ip_header_t* ret, FILE* pcap)
{
	fread(ret, sizeof(ip_header_t), 1, pcap);
}

void get_packet_header (packet_header_t* ret, FILE* pcap)
{
	// packet header
	fread(ret, sizeof(packet_header_t), 1, pcap);
	printf("%u, %u, %u, %u\n", ret->sec, ret->usec, ret->caplen, ret->len);
}

void print_bytes_file(FILE* file, int len)
{
	byte_t *info_check = (byte_t*) malloc(sizeof(byte_t) * len);
	int cnt = 0;
	fread(info_check, sizeof(byte_t), len, file);
	while(cnt <len) {
		for (int i = 0; i<8 && cnt <len; i++) {
			printf("%.2x ", info_check[cnt++]);
		}
		printf("|| ");
		for (int i = 0; i<8 && cnt <len; i++) {
			printf("%2x ", info_check[cnt++]);
		} 
		printf("\n"); 
	}
	free(info_check);
}

void print_bits(u_int32_t u, int len)
{
	int cnt=0;
	for (int i = len-1;i >= 0; i--)
	{
		cnt++;
		printf("%u", u>>i & 0x1);
		if (cnt==4) {
			printf(" ");
		}
		if (cnt==8){
			printf("\n");
			cnt=0;
		}
	}
}

void print_bytes(byte_t* info_check, int len)
{
	int cnt = 0;
	while(cnt <len) {
		for (int i = 0; i<8 && cnt <len; i++) {
			printf("%.2x ", info_check[cnt++]);
		}
		printf("|| ");
		for (int i = 0; i<8 && cnt <len; i++) {
			printf("%2x ", info_check[cnt++]);
		} 
		printf("\n"); 
	}
}

int main(int argc, char* argv[])
{
	// file name from shell
	if (argc!=2) 
	{
		printf("useage: ./packet-parser {file name}");
		exit(1);
	}
	FILE* file = fopen_at_path("../input/", argv[1], "rb");
//	byte_t stream*;
	if (!file)
	{
		printf("no file\n");
		exit(1);
	}
	word_t file_info[24] = {0};
	packet_info_t pcap={0};

	fread(file_info, sizeof(byte_t), 24, file);
	get_packet_header(&pcap.packet_header, file);
	get_ether_info(&pcap.ether_header, file);
	get_ip_info(&pcap.ip_header, file);
	printf("dst_mac: ");
	print_mac_addr(pcap.ether_header.dst);
	printf("src_mac: ");
	print_mac_addr(pcap.ether_header.src);
	printf("src_ip: ");
	print_ip_addr(pcap.ip_header.src);
	printf("dst_ip: ");
	print_ip_addr(pcap.ip_header.dst);
	print_bits(pcap.ip_header.len, 16);

	return 0;
}