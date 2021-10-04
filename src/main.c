#include "../include/read.h"
#include "../include/print.h"
#include "../include/ptype.h"

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