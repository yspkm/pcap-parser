// Computer Network Hw2
// 2017312605 김요셉 ( https://github.com/yspkm/pcap-parser )

#define FILE_NAME "fname.pcap" // 파일 이름 설정용 .  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <bits/types.h>

#define LINE_LEN 61
#define FILE_HEADER_LEN 24

typedef int int32_t;
typedef unsigned u_int32_t;

typedef unsigned char byte_t;
typedef unsigned short hword_t;
typedef unsigned int word_t; // word from MIPS, not x86-64

typedef struct _ehter_header_s
{
	byte_t dst[6];
	byte_t src[6];
	byte_t type[2];
} ether_header_t;

typedef struct _ip_header_s
{
	// 32 bit
	word_t ver : 4;
	word_t ihl : 4;
	word_t tos : 8;
	word_t len : 16;

	// 32 bit
	word_t id : 16;
	word_t frag_info : 16;

	word_t ttl : 8;
	word_t protocol : 8;
	word_t header_checksum : 16;

	// 2 * 32 bit
	byte_t src[4];
	byte_t dst[4];
} ip_header_t;

typedef struct _packet_header_s
{
	u_int32_t sec;	  // small endian
	u_int32_t usec;	  // small endian
	u_int32_t caplen; // captured length (recorded)
	u_int32_t len;	  // packet length (actual)
} packet_header_t;

typedef struct _packet_info_s
{
	packet_header_t packet_header;
	ether_header_t ether_header;
	ip_header_t ip_header;
} packet_info_t;

typedef enum _flag_e
{
	DF,
	MF,
	EF // it means end of frag
} flag_t;

FILE *fopen_at_path(char *pathname, char *filename, char *modes);
void get_ether_info(ether_header_t *ret, FILE *pcap);
void get_ip_info(ip_header_t *ret, FILE *pcap);
void get_packet_header(packet_header_t *ret, FILE *pcap);
// print bytes from FILE*
void print_bytes_file(FILE *file, int len);
// print bytes from bytes array
void print_bytes(byte_t *info_check, int len);
// print bits
void print_bits(u_int32_t u, int len);

//hh:mm:ss.xxxxxx
void print_local_time(packet_header_t *pkthdr);
//e.g. 1.1.1.1
void print_ip_addr(byte_t *ip_addr);
//e.g. aa:aa:aa:aa:aa:aa
void print_mac_addr(byte_t *mac_addr);

//in decimal
u_int32_t get_ttl(ip_header_t *iphdr);
// in flag_t format
flag_t get_ip_flag(ip_header_t *iphdr);
// convert big endian to little endian
u_int32_t hword_to_numeric(hword_t hword);
// in decimal
u_int32_t get_offset(ip_header_t *iphdr);
void print_packet_info(packet_info_t *pcap, int frame_cnt);
void print_line(int num, char a);

// file name
const char *fname = FILE_NAME;

int main(int argc, char *argv[])
{
	int frame_num = 0, cnt_frag = 0, cnt_udp = 0, cnt_tcp = 0, cnt_icmp = 0;
	const size_t READ_BYTES = sizeof(ether_header_t) + sizeof(ip_header_t);
	packet_info_t pcap = {0};
	word_t padding[4096] = {0};
	FILE *file = fopen(fname, "rb");

	// if (argc != 2)
	// {
	// 	printf("useage: ./packet-parser {file name}");
	// 	exit(1);
	// }
	// FILE *file = fopen_at_path("../input/", argv[1], "rb");
	// if (!file)
	// {
	// 	printf("no file\n");
	// 	exit(1);
	// }

	frame_num = 0;
	cnt_frag = 0;
	cnt_tcp = 0;
	cnt_udp = 0;
	cnt_icmp = 0;
	
	hword_t old_id = 0xffff;  
	fread(padding, sizeof(byte_t), FILE_HEADER_LEN, file);
	for (frame_num = 1; !feof(file) ; frame_num++)
	{
		get_packet_header(&pcap.packet_header, file);
		get_ether_info(&pcap.ether_header, file);
		get_ip_info(&pcap.ip_header, file);
		fread(padding, sizeof(byte_t), pcap.packet_header.caplen - READ_BYTES, file);
		// wsl의 파일형식 문제로 추가한 구문입니다. 
		if (feof(file)) {break;}
		print_packet_info(&pcap, frame_num);

		if (get_ip_flag(&pcap.ip_header) != DF)
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
	}
	frame_num--;
	printf("%d Packets(%d TCP | %d UDP | %d ICMP | %d Fragmented)\n",
		   frame_num, cnt_tcp, cnt_udp, cnt_icmp, cnt_frag);

	return 0;
}

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
	printf("%2d:%2d:%2d.%.06u", time->tm_hour, time->tm_min, time->tm_sec, usec);
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
	printf("Flag                | %s", flag == MF ? "MF" : (flag == DF) ? "DF"
																		: "last frag");
	if (flag != DF)
	{
		offset = get_offset(&pcap->ip_header);
		printf(" (offset: %d (%d * 8))\n", offset * 8, offset);
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

FILE *fopen_at_path(char *pathname, char *filename, char *modes)
{
	FILE *ret = NULL;
	int tot_len = strlen(pathname) + strlen(filename); // with '\0'
	char *fname = (char *)malloc(tot_len * sizeof(char));
	strcat(fname, pathname);
	strcat(fname, filename);
	ret = fopen(fname, modes);
	free(fname);
	return ret;
}

void get_ether_info(ether_header_t *ret, FILE *pcap)
{
	fread(ret, sizeof(ether_header_t), 1, pcap);
}

void get_ip_info(ip_header_t *ret, FILE *pcap)
{
	fread(ret, sizeof(ip_header_t), 1, pcap);
}

void get_packet_header(packet_header_t *ret, FILE *pcap)
{
	fread(ret, sizeof(packet_header_t), 1, pcap);
}
