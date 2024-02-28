//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

void	put_hex(unsigned long digest)
{
	uint8_t	hex_c;
	uint8_t	tab[2] = {'0', '0'};
	int		i = 0;

	while (digest)
	{
		hex_c = (char)(digest % 16);
		if (hex_c < 10)
			hex_c += 48;
		else
			hex_c += 87;
		tab[i] = hex_c;
		digest /= 16;
		i++;
	}
	for (; i >= 0; i--)
		ft_putchar_fd(tab[i], 1);
}


void    print_usage()
{
	ft_putstr_fd("help:\n\n", 2);
	ft_putstr_fd("Message Digest commands:\n", 2);
	ft_putstr_fd("md5\n", 2);
	ft_putstr_fd("sha256\n", 2);
	ft_putchar_fd('\n', 2);
}

void	print_result_md5(t_md5 *opt, t_MD5Context *ctx)
{
	(void)opt;
	ft_printf("(stdin)= ");
	for(unsigned int i = 0; i < 4; ++i)
	{
		ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
		ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
		ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
		ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
	}
	for(unsigned int i = 0; i < MD5_DIGEST_LGTH; ++i)
		put_hex(ctx->digest[i]);
	ft_putchar_fd('\n', 1);
}
