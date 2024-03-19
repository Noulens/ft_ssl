//
// Created by tnoulens on 2/20/24.
//

#include "ft_ssl.h"


//ROTATE RIGHT 32 BITS NUMBER
#define ROTRIGHT(a,b) ((a >> b) ^ (a << (32-(b))))
//OPERATION TO CALCULATE CH
#define CH(x,y,z) ((x & y) ^ (z & ~x))
//OPERATION TO CALCULTATE MAJ
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
//OPERATION TO CALCULATE S0
#define S0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ (x >> 3))
//OPERATION TO CALCULATE S1
#define S1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ (x >> 10))

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

/*
 * SHA-224 and SHA-256 use the same sequence of sixty-four constant
 * 32-bit words, K0, K1, ..., K63.  These words represent the first 32
 * bits of the fractional parts of the cube roots of the first sixty-
 * four prime numbers.
 * */
static const uint32_t K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
	0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
	0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
	0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * For SHA-256, the initial hash value, H(0), consists of the following
 * eight 32-bit words, in hex.  These words were obtained by taking the
 * first 32 bits of the fractional parts of the square roots of the
 * first eight prime numbers.
 * */


static const uint8_t PADDING[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void	initSha256Ctx(t_sha256Context *ctx, int opt)
{
	(void)opt;

	ctx->buffer[0] = H0;
	ctx->buffer[1] = H1;
	ctx->buffer[2] = H2;
	ctx->buffer[3] = H3;
	ctx->buffer[4] = H4;
	ctx->buffer[5] = H5;
	ctx->buffer[6] = H6;
	ctx->buffer[7] = H7;
	ctx->size = 0x0;
	ft_memset(ctx->digest, 0, SHA256_DIGEST_LGTH);
	ft_memset(ctx->input, 0, 64);
}

void	sha256_readinput(t_hash *to_digest, t_sha256Context *ctx, int fd)
{
	char    buff[BUFFER_SIZE + 1];
	ssize_t nb_read;
	int     start = 1;

	initSha256Ctx(ctx, to_digest->flags);
	ft_memset(buff, 0, BUFFER_SIZE + 1);
	while ((nb_read = read(fd, buff, BUFFER_SIZE)) >= 0)
	{
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && start == 1 && (to_digest->flags & e_p) && ft_printf("(\""));
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && (to_digest->flags & e_p) && (start = 0));
		buff[nb_read] = 0;
		sha256(ctx, buff, nb_read);
		if (nb_read && nb_read < BUFFER_SIZE && buff[nb_read - 1] == '\n')
			buff[nb_read - 1] = 0;
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && !start && (to_digest->flags & e_p) && ft_printf("%s", buff));
		if (nb_read == 0)
			break;
		ft_memset(buff, 0, BUFFER_SIZE + 1);
	}
	if (nb_read == -1)
	{
		error("ft_ssl: read: ", errno, FALSE);
		clean_opt_hash(to_digest);
		exit(1);
	}
	else
	{
		sha256append(ctx);
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && !start && (to_digest->flags & e_p) && ft_printf("\")= "));
	}
}

void	sha256rounds(t_sha256Context *ctx, uint8_t *W, int opt)
{
	uint32_t	m[64] __attribute__((aligned(16))) = {};
	uint32_t	i = 0;
	uint32_t	j = 0;
	uint32_t	T1;
	uint32_t	T2;
	uint32_t	A = ctx->buffer[a];
	uint32_t	B = ctx->buffer[b];
	uint32_t	C = ctx->buffer[c];
	uint32_t	D = ctx->buffer[d];
	uint32_t	E = ctx->buffer[e];
	uint32_t	F = ctx->buffer[f];
	uint32_t	G = ctx->buffer[g];
	uint32_t	H = ctx->buffer[h];

	if (opt)
	{
		uint64_t	bitLen = ctx->size * 8;

		W[56] = (bitLen >> 56);
		W[57] = (bitLen >> 48);
		W[58] = (bitLen >> 40);
		W[59] = (bitLen >> 32);
		W[60] = (bitLen >> 24);
		W[61] = (bitLen >> 16);
		W[62] = (bitLen >> 8);
		W[63] = bitLen;
	}
	for (; i < 16; ++i, j += 4)
		m[i] = W[j] << 24 | W[j + 1] << 16 | W[j + 2] << 8 | W[j + 3];
	for (size_t t = 16; t < 64; t++)
		m[t] = S1(m[t - 2]) + m[t - 7] + S0(m[t - 15]) + m[t - 16];
	for (size_t t = 0; t < 64; t++)
	{
		T1 = H + EP1(E) + CH(E, F, G) + K[t] + m[t];
		T2 = EP0(A) + MAJ(A, B, C);
		H = G;
		G = F;
		F = E;
		E = D + T1;
		D = C;
		C = B;
		B = A;
		A = T1 + T2;
	}
	ctx->buffer[a] += A;
	ctx->buffer[b] += B;
	ctx->buffer[c] += C;
	ctx->buffer[d] += D;
	ctx->buffer[e] += E;
	ctx->buffer[f] += F;
	ctx->buffer[g] += G;
	ctx->buffer[h] += H;
}

void	sha256append(t_sha256Context *ctx)
{
	size_t		len;
	size_t      bits_to_add;
	uint8_t     *full_message = NULL;
	uint8_t     *offset = NULL;

	bits_to_add = bitsToAdd(ctx->final_len);
	full_message = (uint8_t *)malloc(ctx->final_len + bits_to_add / 8 + sizeof(uint64_t) + 1);
	if (!full_message)
		error("sha256 func", errno, TRUE);
	full_message[ctx->final_len + bits_to_add / 8 + 8] = 0;
	ft_memcpy(full_message, ctx->input, ctx->final_len);
	ft_memcpy(full_message + ctx->final_len, PADDING, bits_to_add / 8);
	len = ctx->final_len + bits_to_add / 8 + sizeof(uint64_t);
	for (size_t i = 0; i < len; i += 64)
	{
		offset = full_message + i;
		sha256rounds(ctx, offset, i == len - 64 ? TRUE : FALSE);
	}
	free(full_message);
	full_message = offset = NULL;
}

void	sha256(t_sha256Context *ctx, char *s, size_t l)
{
	uint8_t		*offset = NULL;
	size_t		len;

	offset = (uint8_t *)s;
	len = l;
	if (s && len)
	{
		while (len >= 64)
		{
			sha256rounds(ctx, offset, FALSE);
			ctx->size += 64;
			offset += 64;
			len -= 64;
		}
		ctx->size += len;
		ctx->final_len = len;
		ft_memcpy(ctx->input, offset, len);
	}
}
