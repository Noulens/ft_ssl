//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

static uint32_t ABCD[4] =
{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

/*static uint32_t	S[64] =
{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};*/

static uint32_t	K[64] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static uint8_t PADDING[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void	MD5ctx_init(t_MD5Context *ctx)
{
	ctx->size = 0x0;
	ctx->buffer[0] = ABCD[0];
	ctx->buffer[1] = ABCD[1];
	ctx->buffer[2] = ABCD[2];
	ctx->buffer[3] = ABCD[3];
	ft_bzero(ctx->buffer, 64);
}

char *md5(char *s, int flags)
{
	t_MD5Context	ctx = {0};

	if (!(flags & e_little))
	{
		reverseEndiannessArray32(K, 64);
		reverseEndiannessArray32(ABCD, 4);
	}
	MD5ctx_init(&ctx);
	uint64_t len = ft_strlen(s);
	//TODO
	printf("LEN: %lu\n", len);
	// We want the number of bits of the string + 512 as a base to know the next multiple of 512
	size_t bits = len * 8 + 512;
	// to know the next X multiple after n: (n + (X - 1)) - ((n + (X - 1)) % X)
	// then we subtract len * 8 - 64 to have the next value congruent to 448 modulo 512
	// this gives the number of bits to add to have a length 64 bits short of 512
	size_t bits_to_add = ((bits + 511) - ((bits + 511) % 512)) - len * 8 - 64;
	//TODO
	ft_printf("Mod: %d\n", bits_to_add);
	uint8_t *full_message = (uint8_t *)malloc(len + bits_to_add / 8 + sizeof(uint64_t) + 1);
	if (!full_message)
	{
		error("md5 func", errno, FALSE);
		return (NULL);
	}
	full_message[len + bits_to_add / 8 + 8] = 0;
	ft_memcpy(full_message, s, len);
	ft_memcpy(full_message + len, PADDING, bits_to_add / 8);
	if (!(flags & e_little))
		reverseEndiannessArray64(&len, 1);
	ft_memcpy(full_message + len + bits_to_add / 8, (uint8_t *)&len, sizeof(uint64_t));
//	ft_printf("%s\n", full_message);
	// this to check that the final message has the len at the end:
/*	uint64_t bob = 0;
	for (size_t i = len + bits_to_add / 8; i < len + bits_to_add / 8 + sizeof(uint64_t); i++)
	{
		bob |= full_message[i];
	}
	printf("Appended len: %lu, total len %% 512 = %lu\n", bob, (len * 8 + bits_to_add + 64) % 512);
	free(full_message);
	full_message = NULL;*/
//	printf("%s\n", full_message);
	uint32_t		chunk[MD5_DIGEST_LGTH];
	ft_memset(chunk, 0x0, sizeof(chunk));
	for (size_t j = 0; j < MD5_DIGEST_LGTH; j++)
	{
		chunk[j] |= (uint8_t)full_message[j * 4] | (full_message[j * 4 + 1] << 8) | (full_message[j * 4 + 2] << 16) | (full_message[j * 4 + 3] << 24);
		printf("0x%x\n", chunk[j]);
	}
	if (!(flags & e_little))
		reverseEndiannessArray32(chunk, MD5_DIGEST_LGTH);
	
	return ("ok\n");
}

uint32_t	F(t_word X, t_word Y, t_word Z)
{
	return ((X.w & Y.w) | (~X.w & Z.w));
}

uint32_t	G(t_word X, t_word Y, t_word Z)
{
	return ((X.w & Z.w) | (Y.w & ~Z.w));
}

uint32_t	H(t_word X, t_word Y, t_word Z)
{
	return (X.w ^ Y.w ^ Z.w);
}

uint32_t	I(t_word X, t_word Y, t_word Z)
{
	return (Y.w ^ (X.w | ~Z.w));
}

/*
 * Rotates a 32-bit word left by n bits
 */

uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32 - n));
}
