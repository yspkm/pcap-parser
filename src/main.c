#include "../include/read.h"
#include "../include/print.h"
#include "../include/ptype.h"

// file name from shell
int main(int argc, char *argv[])
{
	int frame_num = 0, cnt_frag = 0, cnt_udp = 0, cnt_tcp = 0, cnt_icmp = 0;
	const size_t READ_BYTES = sizeof(ether_header_t) + sizeof(ip_header_t);
	packet_info_t pcap = {0};
	word_t padding[4096] = {0};

	if (argc != 2)
	{
		printf("useage: ./packet-parser {file name}");
		exit(1);
	}
	FILE *file = fopen_at_path("../input/", argv[1], "rb");
	if (!file)
	{
		printf("no file\n");
		exit(1);
	}

	frame_num = 0;
	cnt_frag = 0;
	cnt_tcp = 0;
	cnt_udp = 0;
	cnt_icmp = 0;

	fread(padding, sizeof(byte_t), 24, file);
	get_packet_header(&pcap.packet_header, file);
	get_ether_info(&pcap.ether_header, file);
	get_ip_info(&pcap.ip_header, file);
	fread(padding, sizeof(byte_t), pcap.packet_header.caplen - READ_BYTES, file);

	while (!feof(file))
	{
		frame_num++; // 1, 2, 3.. as in Wireshark
		print_packet_info(&pcap, frame_num);

		if (get_ip_flag(&pcap.ip_header) != DF && get_offset(&pcap.ip_header))
		{
			cnt_frag++;
		}
		switch (pcap.ip_header.protocol)
		{
		case 1:
			cnt_icmp++;
			break;
		case 6:
			cnt_tcp++;
			break;
		case 17:
			cnt_udp++;
			break;
		}

		get_packet_header(&pcap.packet_header, file);
		get_ether_info(&pcap.ether_header, file);
		get_ip_info(&pcap.ip_header, file);
		fread(padding, sizeof(byte_t), pcap.packet_header.caplen - READ_BYTES, file);
	}
	printf("%d Packets(%d TCP | %d UDP | %d ICMP | %d Fragmented)\n",
		   frame_num, cnt_tcp, cnt_udp, cnt_icmp, cnt_frag);

	return 0;
}