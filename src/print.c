#include "../include/print.h"

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

void print_ip_addr(byte_t* ip_addr)
{
	for (int i = 0;i < 4; i++)
	{
		printf("%d", ip_addr[i]);
		if (i !=3 ) {
			printf(".");
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
		}
	}
}

void print_local_time(packet_header_t* pkthdr)
{
	time_t sec = (time_t) pkthdr->sec; 
	struct tm *time = localtime(&sec);
	u_int32_t usec = pkthdr->usec;
	printf("%2d:%2d:%2d.%.06u", time->tm_hour, time->tm_min, time->tm_sec, usec);
}

u_int32_t hword_to_numeric(hword_t hword)
{
	byte_t tmp;
	byte_t* byte_ptr = (byte_t*) & hword;

	tmp = byte_ptr[0];
	byte_ptr[0] = byte_ptr[1];
	byte_ptr[1] = tmp;

	return (u_int32_t) hword;
}

flag_t get_ip_flag(ip_header_t* iphdr)
{
	flag_t ret;
	word_t frag_info = iphdr->frag_info; 

	if ((frag_info>>6) & 0x1)
	{
		ret = DF;
	} else
	{
		ret = EF;
	}
	return ret;
}

u_int32_t get_offset(ip_header_t* iphdr)
{
	hword_t ret = 0xef;
	print_bits(ret, 16);
	// = iphdr->frag_info;

	hword_t msk_r = 0xffff ^ 0x1 << 7;
	hword_t msk_d = 0xffff ^ 0x1 << 5;
	hword_t msk_m = 0xffff ^ 0x1 << 6;
	ret &= msk_r & msk_d & msk_m;
	
	return (u_int32_t) hword_to_numeric(ret);
}

void print_line(int num, char a) 
{
	for (int i = 0; i < num; i++)
	{
		printf("%c", a);
	}
}