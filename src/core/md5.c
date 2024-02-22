//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

static uint32_t ABCD[4] =
		{
				0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
		};

static uint32_t S[64] =
		{
				7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
		};

static uint32_t T[64] =
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

void MD5ctx_init(t_MD5Context *ctx)
{
	ctx->size = 0x0;
	ctx->buffer[A] = ABCD[A];
	ctx->buffer[B] = ABCD[B];
	ctx->buffer[C] = ABCD[C];
	ctx->buffer[D] = ABCD[D];
}

void rotate_buffers(t_MD5Context *ctx)
{
	uint32_t tmp = 0;
	tmp = (*ctx).buffer[D];
	for (int rotb = 3; rotb > 0; rotb--)
		(*ctx).buffer[rotb] = (*ctx).buffer[rotb - 1];
	(*ctx).buffer[A] = tmp;
}

char *md5(char *s, int flags)
{
	t_MD5Context	ctx;
	uint32_t		X[16];
	uint8_t			*offset = NULL;

	if (!(flags & e_little))
	{
		reverseEndiannessArray32(T, 64);
		reverseEndiannessArray32(S, 64);
		reverseEndiannessArray32(ABCD, 4);
	}
	MD5ctx_init(&ctx);
	rotate_buffers(&ctx);
	printf("test rotate %x %x %x %x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
	uint64_t len = ft_strlen(s);
	//TODO
	printf("LEN: %lu\n", len);
	size_t bits = len * 8;
	// to know the next X multiple after n: (n + (X - 1)) - ((n + (X - 1)) % X)
	size_t bits_to_add;
	if (!len)
		bits_to_add = 448;
	else
	{
		bits_to_add = ((bits + 511) - ((bits + 511) % 512)) - len * 8;
		if (bits_to_add % 512 == 0)
			bits_to_add = 448;
		else
			bits_to_add = bits_to_add - 64;
	}
	//TODO
	ft_printf("to add: %d\n", bits_to_add);
	uint8_t *full_message = (uint8_t *) malloc(
			len + bits_to_add / 8 + sizeof(uint64_t) + 1);
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
	ft_memcpy(full_message + len + bits_to_add / 8, (uint8_t *) &len,
			  sizeof(uint64_t));
	// we loop on the full message and increment by 64 bytes
	printf("msg len %lu\n", len + bits_to_add / 8 + sizeof(uint64_t));
//	uint64_t bob = 0;
//	for (size_t i = 0; i < sizeof(uint64_t); i++) {
//		bob |= (uint64_t)full_message[len + bits_to_add / 8 + i] << (i * 8);
//	}
//	printf("Appended len: %lu, total len %% 512 = %lu\n", bob, (len * 8 + bits_to_add + 64) % 512);
	for (size_t i = 0; i < len + bits_to_add / 8 + sizeof(uint64_t); i += 64)
	{
		// we offset the message
		offset = full_message + i;
		// now we have to split into sixteen 32-bit “words” the message of 512 bits
		ft_memset(X, 0x0, sizeof(X));
		for (size_t j = 0; j < 16; j++)
			X[j] |= offset[j * 4]
					| (offset[j * 4 + 1] << 8)
					| (offset[j * 4 + 2] << 16)
					| (offset[j * 4 + 3] << 24);
		if (!(flags & e_little))
			reverseEndiannessArray32(X, 16);
		// we start the loop
		printf("Block of 512 #%lu %x %x %x %x\n", i, ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
		for (size_t k = 0; k < 16; k++)
		{
			// now we proceed to the rounds
			/* Save A as AA, B as BB, C as CC, and D as DD. */
			uint32_t AA = ctx.buffer[A];
			uint32_t BB = ctx.buffer[B];
			uint32_t CC = ctx.buffer[C];
			uint32_t DD = ctx.buffer[D];
			for (size_t l = 0; l < 16; l++)
			{
				ctx.buffer[A] = ctx.buffer[B] +
								(rotateLeft(ctx.buffer[A] +
								F(ctx.buffer[B], ctx.buffer[C],ctx.buffer[D]) +
								X[l] + T[l], S[l]));
//				printf("%x %x %x %x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
				rotate_buffers(&ctx);
			}
			rotate_buffers(&ctx);
			for (size_t l = 0; l < 16; l++)
			{
				ctx.buffer[A] = ctx.buffer[B] +
								(rotateLeft(ctx.buffer[A] +
								G(ctx.buffer[B], ctx.buffer[C],ctx.buffer[D]) +
								X[(l * 5 + 1) % 16] + T[l + 16], S[l + 16]));
//				printf("%x %x %x %x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
				rotate_buffers(&ctx);
			}
			rotate_buffers(&ctx);
			for (size_t l = 0; l < 16; l++)
			{
				ctx.buffer[A] = ctx.buffer[B] +
								(rotateLeft(ctx.buffer[A] +
								H(ctx.buffer[B], ctx.buffer[C],ctx.buffer[D]) +
								X[(l * 3 + 5) % 16] + T[l + 32], S[l + 32]));
//				printf("%x %x %x %x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
				rotate_buffers(&ctx);
			}
			rotate_buffers(&ctx);
			/* Round 4. */
			/* Let [abcd k s t] denote the operation
				 a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
			/* Do the following 16 operations.
			[ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
			[ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
			[ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
			[ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]*/
			for (size_t l = 0; l < 16; l++)
			{
				ctx.buffer[A] = ctx.buffer[B] +
								(rotateLeft(ctx.buffer[A] +
								I(ctx.buffer[B], ctx.buffer[C],ctx.buffer[D]) +
								X[(l * 7) % 16] + T[l + 48], S[l + 48]));
//				printf("%x %x %x %x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
				rotate_buffers(&ctx);
			}
			rotate_buffers(&ctx);
			/* Then perform the following additions. (That is increment each
			 * of the four registers by the value it had before this block
			 * was started.) */
			ctx.buffer[A] += AA;
			ctx.buffer[B] += BB;
			ctx.buffer[C] += CC;
			ctx.buffer[D] += DD;
		}
	}
	printf("FINAL:\n%x%x%x%x\n", ctx.buffer[A], ctx.buffer[B], ctx.buffer[C], ctx.buffer[D]);
	free(full_message);
	full_message = NULL;
	offset = NULL;
	return ("ok\n");
}

uint32_t F(uint32_t X, uint32_t Y, uint32_t Z)
{
	return ((X & Y) | (~X & Z));
}

uint32_t G(uint32_t X, uint32_t Y, uint32_t Z)
{
	return ((X & Z) | (Y & ~Z));
}

uint32_t H(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (X ^ Y ^ Z);
}

uint32_t I(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (Y ^ (X | ~Z));
}

/*
 * Rotates a 32-bit word left by n bits
 */

uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32 - n));
}
