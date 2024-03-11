//
// Created by tnoulens on 2/20/24.
//

#include "ft_ssl.h"

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
static const uint32_t Initial[8] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void	initSha256Ctx(t_sha256Context *ctx, int opt)
{
	(void)opt;
	ctx->buffer[A] = Initial[A];
	ctx->buffer[B] = Initial[B];
	ctx->buffer[C] = Initial[C];
	ctx->buffer[D] = Initial[D];
	ctx->buffer[E] = Initial[A];
	ctx->buffer[F] = Initial[B];
	ctx->buffer[G] = Initial[C];
	ctx->buffer[H] = Initial[D];
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
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && !start && (to_digest->flags & e_p) && ft_printf("%s", buff));
		sha256(ctx, buff, to_digest->flags, nb_read);
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
//		md5append(ctx, to_digest->flags);
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && !start && (to_digest->flags & e_p) && ft_printf("\") = "));
	}
}

void	sha256(t_sha256Context *ctx, char *s, int flags, size_t len)
{
	uint32_t	W[64];

	if (s && len)
	{

	}
}

uint32_t	CH(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint32_t	MAJ(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint32_t	BSIG0(uint32_t x)
{
	return (rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22));
}

uint32_t	BSIG1(uint32_t x)
{
	return (rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25));
}

uint32_t	SSIG0(uint32_t x)
{
	return (rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3));
}

uint32_t	SSIG1(uint32_t x)
{
	return (rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10));
}
