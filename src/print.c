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
