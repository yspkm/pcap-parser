#include "../include/print.h"

void print_bytes_file(FILE *file, int len)
{
	byte_t *info_check = (byte_t *)malloc(sizeof(byte_t) * len);
	int cnt = 0;
	fread(info_check, sizeof(byte_t), len, file);
	while (cnt < len)
	{
		for (int i = 0; i < 8 && cnt < len; i++)
		{
			printf("%.2x ", info_check[cnt++]);
		}
		printf("|| ");
		for (int i = 0; i < 8 && cnt < len; i++)
		{
			printf("%2x ", info_check[cnt++]);
		}
		printf("\n");
	}
	free(info_check);
}

void print_bits(u_int32_t u, int len)
{
	int cnt = 0;
	for (int i = len - 1; i >= 0; i--)
	{
		cnt++;
		printf("%u", u >> i & 0x1);
		if (cnt == 4)
		{
			printf(" ");
		}
		if (cnt == 8)
		{
			printf("\n");
			cnt = 0;
		}
	}
}

void print_bytes(byte_t *info_check, int len)
{
	int cnt = 0;
	while (cnt < len)
	{
		for (int i = 0; i < 8 && cnt < len; i++)
		{
			printf("%.2x ", info_check[cnt++]);
		}
		printf("|| ");
		for (int i = 0; i < 8 && cnt < len; i++)
		{
			printf("%2x ", info_check[cnt++]);
		}
		printf("\n");
	}
}

void print_ip_addr(byte_t *ip_addr)
{
	for (int i = 0; i < 4; i++)
	{
		printf("%d", ip_addr[i]);
		if (i != 3)
		{
			printf(".");
		}
	}
}

void print_mac_addr(byte_t *mac_addr)
{
	for (int i = 0; i < 6; i++)
	{
		printf("%.2x", mac_addr[i]);
		if (i != 5)
		{
			printf(":");
		}
	}
}

void print_local_time(packet_header_t *pkthdr)
{
	time_t sec = (time_t)pkthdr->sec;
	struct tm *time = localtime(&sec);
	u_int32_t usec = pkthdr->usec;
	printf("%.02d:%.02d:%.02d.%.06u", time->tm_hour, time->tm_min, time->tm_sec, usec);
}

u_int32_t hword_to_numeric(hword_t hword)
{
	byte_t tmp;
	byte_t *byte_ptr = (byte_t *)&hword;

	tmp = byte_ptr[0];
	byte_ptr[0] = byte_ptr[1];
	byte_ptr[1] = tmp;

	return (u_int32_t)hword;
}

flag_t get_ip_flag(ip_header_t *iphdr)
{
	flag_t ret;
	word_t frag_info = iphdr->frag_info;

	if ((frag_info >> 6) & 0x1)
	{
		ret = DF;
	}
	else if ((frag_info >> 5) & 0x1)
	{
		ret = MF;
	}
	else
	{
		ret = EF;
	}
	return ret;
}

u_int32_t get_offset(ip_header_t *iphdr)
{
	hword_t ret = iphdr->frag_info;

	hword_t msk_r = 0xffff ^ 0x1 << 7;
	hword_t msk_d = 0xffff ^ 0x1 << 5;
	hword_t msk_m = 0xffff ^ 0x1 << 6;
	ret &= msk_r & msk_d & msk_m;

	return (u_int32_t)hword_to_numeric(ret);
}

void print_line(int num, char a)
{
	for (int i = 0; i < num; i++)
	{
		printf("%c", a);
	}
}

void print_packet_info(packet_info_t *pcap, int frame_cnt)
{
	static char *ip_protocol_name[256] = {
		"HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP",
		"BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS",
		"HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4",
		"NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++",
		"IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GRE", "DSR", "BNA",
		"ESP", "AH", "I-NLSP", "SwIPe", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP",
		"IPv6-NoNxt", "IPv6-Opts", "null", "CFTP", "null", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC",
		"null", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND",
		"WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP/IPTM", "NSFNET-IGP", "DGP", "TCF",
		"EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25", "OS", "MICP", "SCC-SP", "ETHERIP",
		"ENCAP", "null", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N",
		"IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "null", "L2TP", "DDX", "IATP",
		"STP", "SRP", "UTI", "SMP", "SM", "PTP", "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE",
		"IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP", "manet",
		"HIP", "Shim6", "WESP", "ROHC", "Ethernet", "Etherne", NULL};

	flag_t flag = 0;
	u_int32_t offset = 0;

	print_line(LINE_LEN, '=');
	printf("\n");
	printf("<Frame %d>\n", frame_cnt);
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("Local Time:         | ");
	print_local_time(&pcap->packet_header);
	printf("\n");
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("Captured Length     | %u\n", pcap->packet_header.caplen);
	printf("Actual Length       | %u\n", pcap->packet_header.len);
	printf("Length in IP Header | %u\n", hword_to_numeric(pcap->ip_header.len));
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("MAC Address         | ");
	print_mac_addr(pcap->ether_header.src);
	printf(" --> ");
	print_mac_addr(pcap->ether_header.dst);
	printf("\n");
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("IP Address          | ");
	print_ip_addr(pcap->ip_header.src);
	printf(" --> ");
	print_ip_addr(pcap->ip_header.dst);
	printf("\n");
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("Protocol            | %s (%d)\n", ip_protocol_name[pcap->ip_header.protocol], pcap->ip_header.protocol);
	print_line(LINE_LEN, '-');
	printf("\n");
	printf("Identification      | %u\n", hword_to_numeric(pcap->ip_header.id));
	print_line(LINE_LEN, '-');
	printf("\n");

	flag = get_ip_flag(&pcap->ip_header);
	printf("Flag                | %s ", flag == MF ? "MF" : (flag == DF) ? "DF":"  ");
	if (flag != DF && pcap->ip_header.frag_info)
	{
		offset = get_offset(&pcap->ip_header);
		if (offset)
		{
			printf("| offset: %d (%d)\n", offset, offset * 8);
		} 
		else
		{
			printf("| offset: 0\n");
		}
	}
	else
	{
		printf("\n");
	}
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("TTL                 | %u\n", pcap->ip_header.ttl);
	print_line(LINE_LEN, '-');
	printf("\n");

	printf("\n");
}