//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

static uint32_t ABCD[4] =
{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
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

void	rotate_buffers(t_MD5Context *ctx)
{
	uint32_t	tmp = 0;

	tmp = (*ctx).buffer[D];
	for (int rotb = 3; rotb > 0; rotb--)
		(*ctx).buffer[rotb] = (*ctx).buffer[rotb - 1];
	(*ctx).buffer[A] = tmp;
}

void	MD5ctx_init(t_MD5Context *ctx)
{
	ctx->size = 0x0;
	ctx->buffer[A] = ABCD[A];
	ctx->buffer[B] = ABCD[B];
	ctx->buffer[C] = ABCD[C];
	ctx->buffer[D] = ABCD[D];
	ft_memset(ctx->digest, 0, MD5_DIGEST_LGTH);
	ft_memset(ctx->input, 0, 64);
}

void md5rounds(t_MD5Context *ctx, const uint32_t *X)
{
	uint32_t AA = ctx->buffer[A];
	uint32_t BB = ctx->buffer[B];
	uint32_t CC = ctx->buffer[C];
	uint32_t DD = ctx->buffer[D];
	for (size_t l = 0; l < 16; l++)
	{
		ctx->buffer[A] = ctx->buffer[B] +
						rotateLeft(ctx->buffer[A] +
						F(ctx->buffer[B], ctx->buffer[C],ctx->buffer[D]) +
						X[l] + T[l], S[l]);
		rotate_buffers(ctx);
	}
	for (size_t l = 0; l < 16; l++)
	{
		ctx->buffer[A] = ctx->buffer[B] +
						rotateLeft(ctx->buffer[A] +
						G(ctx->buffer[B], ctx->buffer[C],ctx->buffer[D]) +
						X[(l * 5 + 1) % 16] + T[l + 16], S[l + 16]);
		rotate_buffers(ctx);
	}
	for (size_t l = 0; l < 16; l++)
	{
		ctx->buffer[A] = ctx->buffer[B] +
						rotateLeft(ctx->buffer[A] +
						H(ctx->buffer[B], ctx->buffer[C],ctx->buffer[D]) +
						X[(l * 3 + 5) % 16] + T[l + 32], S[l + 32]);
		rotate_buffers(ctx);
	}
	for (size_t l = 0; l < 16; l++)
	{
		ctx->buffer[A] = ctx->buffer[B] +
						rotateLeft(ctx->buffer[A] +
						I(ctx->buffer[B], ctx->buffer[C],ctx->buffer[D]) +
						X[(l * 7) % 16] + T[l + 48], S[l + 48]);
		rotate_buffers(ctx);
	}
	ctx->buffer[A] += AA;
	ctx->buffer[B] += BB;
	ctx->buffer[C] += CC;
	ctx->buffer[D] += DD;
}

void splitInWords(int flags, uint32_t *X, const uint8_t *full_message)
{
	ft_memset(X, 0x0, 16 * sizeof(uint32_t));
	for (size_t j = 0; j < 16; j++)
		X[j] |= full_message[j * 4]
		        | (full_message[j * 4 + 1] << 8)
		        | (full_message[j * 4 + 2] << 16)
		        | (full_message[j * 4 + 3] << 24);
	if (!(flags & e_little))
		reverseEndiannessArray32(X, 16);
}

void	md5(t_MD5Context *ctx, char *s, int flags, size_t l)
{
	uint32_t		X[16];
	uint8_t			*offset = NULL;
	size_t			len;

	if (s && l)
	{
		if (!(flags & e_little))
		{
			reverseEndiannessArray32(ctx->buffer, 4);
		}
		offset = (uint8_t *)s;
		len = l;
		while (len >= 64)
		{
			splitInWords(flags, X, offset);
			md5rounds(ctx, X);
			ctx->size += 64;
			offset += 64;
			len -= 64;
		}
		ctx->size += len;
		ctx->final_len = len;
//		printf("ctx.size: %ld\n", ctx->size);
//		printf("offset len: %ld\n", len);
		ft_memcpy(ctx->input, offset, len);
	}
}

size_t bitsToAdd(size_t len)
{
	size_t bits = len * 8;
	size_t bits_to_add;

	if (!len)
		bits_to_add = 448;
	else
	{
		bits_to_add = ((bits + 511) - ((bits + 511) % 512)) - len * 8;
		if (bits_to_add % 512 == 0)
			bits_to_add = 448;
		else
		{
			if (bits_to_add <= 64)
				bits_to_add = 448 + bits_to_add;
			else
				bits_to_add = bits_to_add - 64;
		}
	}
	return bits_to_add;
}

void	md5append(t_MD5Context *ctx, int flags)
{
	size_t		len;
	uint32_t	X[16];
	size_t      bits_to_add;
	uint8_t     *full_message = NULL;
	uint8_t     *offset = NULL;

//	printf("A: %02x B: %02x C: %02x D: %02x\n", ctx->buffer[A], ctx->buffer[B], ctx->buffer[C], ctx->buffer[D]);
//	printf("final len %ld\n", ctx->final_len);
	bits_to_add = bitsToAdd(ctx->final_len);
//	printf("Bits to add: %ld\n", bits_to_add);
	full_message = (uint8_t *) malloc(ctx->final_len + bits_to_add / 8 + sizeof(uint64_t) + 1);
	if (!full_message)
		error("md5 func", errno, TRUE);
	full_message[ctx->final_len + bits_to_add / 8 + 8] = 0;
	ft_memcpy(full_message, ctx->input, ctx->final_len);
	ft_memcpy(full_message + ctx->final_len, PADDING, bits_to_add / 8);
	if (!(flags & e_little))
		reverseEndiannessArray64(&ctx->size, 1);
	len = ctx->final_len + bits_to_add / 8 + sizeof(uint64_t);
	for (size_t i = 0; i < len; i += 64)
	{
		offset = full_message + i;
		splitInWords(flags, X, offset);
		if (i == len - 64)
		{
			X[14] = (uint32_t)(ctx->size * 8);
			X[15] = (uint32_t)((ctx->size * 8) >> 32);
//			print_full_message(full_message, len + bits_to_add / 8);
//			print_full_message((uint8_t *)(X + 14), sizeof(uint64_t));
//			uint64_t bob = 0;
//			bob |= (uint64_t)X[15] << 32;
//			bob |= X[14];
//			uint64_t bob2 = bob / 8;
//			printf("len before 64 bits of len: %lu\n", len * 8 + bits_to_add);
//			printf("BOB: %lx, Bob/8: %lu, bob/8 *8: %lu\n", bob, bob2, bob2 * 8);
		}
		md5rounds(ctx, X);
	}
	free(full_message);
	full_message = offset = NULL;
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

uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32 - n));
}
