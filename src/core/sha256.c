//
// Created by tnoulens on 2/20/24.
//

#include "ft_ssl.h"

void	sha256_readinput(t_hash *to_digest, t_sha256Context *ctx, int fd)
{
	char    buff[BUFFER_SIZE + 1];
	ssize_t nb_read;
	int     start = 1;

	(void)ctx;
//	MD5ctx_init(ctx);
	ft_memset(buff, 0, BUFFER_SIZE + 1);
	while ((nb_read = read(fd, buff, BUFFER_SIZE)) >= 0)
	{
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && start == 1 && (to_digest->flags & e_p) && ft_printf("(\""));
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && (to_digest->flags & e_p) && (start = 0));
		buff[nb_read] = 0;
		(void)(!(to_digest->flags & e_file) && !(to_digest->flags & e_q) && !start && (to_digest->flags & e_p) && ft_printf("%s", buff));
//		md5(ctx, buff, to_digest->flags, nb_read);
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
