#ifndef PTYPE_H
#define PTYPE_H

#include <bits/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#endif