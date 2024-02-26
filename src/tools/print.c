//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

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
	ft_putstr_fd("(stdin)= ", 1);
	for(unsigned int i = 0; i < 4; ++i)
	{
		ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
		ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
		ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
		ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
	}
	for(unsigned int i = 0; i < 16; ++i)
	{
		printf("%02x", ctx->digest[i]);
	}
	printf("\n");
}
