#include "../include/read.h"
#include "../include/print.h"
#include "../include/ptype.h"

char *g_ip_protocol_name[] = {"HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GRE", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SwIPe", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "null", "CFTP", "null", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", "null", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP/IPTM", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25", "OS", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "null", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "null", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP", "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC", "Ethernet", "Etherne", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

// file name from shell
int main(int argc, char *argv[])
{
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
	word_t buffer[4096] = {0};
	packet_info_t pcap = {0};
	flag_t flag;
	size_t read_bytes = 0;
	fread(buffer, sizeof(byte_t), 24, file);
	int cnt=0;
	const int LINE_LEN = 61;
	while (!feof(file))
	{
		cnt++;
		printf("\n"); print_line(LINE_LEN, '='); printf("\n"); 
		printf("<Frame %d>\n", cnt);
		print_line(LINE_LEN, '-'); printf("\n"); 
		get_packet_header(&pcap.packet_header, file);
		read_bytes = 0;
		read_bytes += get_ether_info(&pcap.ether_header, file);
		read_bytes += get_ip_info(&pcap.ip_header, file);
		fread(buffer, sizeof(byte_t), pcap.packet_header.caplen - read_bytes, file);

		printf("Local Time:         | ");
		print_local_time(&pcap.packet_header);
		printf("\n"); print_line(LINE_LEN, '-'); printf("\n"); 

		printf("captured length     | %u\n", pcap.packet_header.caplen);
		printf("actual length       | %u\n", pcap.packet_header.len);
		printf("length in IP header | %u\n", hword_to_numeric(pcap.ip_header.len));
		print_line(LINE_LEN, '-'); printf("\n"); 

		printf("MAC Address         | ");
		print_mac_addr(pcap.ether_header.src);
		printf(" --> ");
		print_mac_addr(pcap.ether_header.dst);
		printf("\n"); print_line(LINE_LEN, '-'); printf("\n"); 

		printf("IP Address          | ");
		print_ip_addr(pcap.ip_header.src);
		printf(" --> ");
		print_ip_addr(pcap.ip_header.dst);
		printf("\n"); print_line(LINE_LEN, '-'); printf("\n"); 

		printf("Protocol            | %u (%s)\n", pcap.ip_header.protocol, g_ip_protocol_name[pcap.ip_header.protocol]);
		print_line(LINE_LEN, '-'); printf("\n"); 
		printf("Identification      | %u\n", hword_to_numeric(pcap.ip_header.id));
		print_line(LINE_LEN, '-'); printf("\n"); 
		flag = get_ip_flag(&pcap.ip_header);
		printf("flag                | %s\n", flag == MF ? "MF" : (flag == DF) ? "DF":"");
		print_line(LINE_LEN, '-'); printf("\n"); 
		printf("TTL                 | %u\n", pcap.ip_header.ttl);
		print_line(LINE_LEN, '='); printf("\n"); 
	}

	return 0;
}