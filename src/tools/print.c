//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

static void	put_hex(unsigned long digest)
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
	ft_putchar_fd((char)tab[1], 1);
	ft_putchar_fd((char)tab[0], 1);
}

int	set_digest(uint8_t *digest, const uint32_t *buffer, size_t len)
{
	switch (len)
	{
		case MD5_DIGEST_LGTH:
			for (unsigned int i = 0; i < len / 4; ++i)
			{
				digest[(i * 4) + 0] = (uint8_t)(((buffer[i]) & 0x000000FF));
				digest[(i * 4) + 1] = (uint8_t)(((buffer[i]) & 0x0000FF00) >>  8);
				digest[(i * 4) + 2] = (uint8_t)(((buffer[i]) & 0x00FF0000) >> 16);
				digest[(i * 4) + 3] = (uint8_t)(((buffer[i]) & 0xFF000000) >> 24);
			}
			return (0) ;
		case SHA256_DIGEST_LGTH:
			for (unsigned int i = 0; i < len / 4; ++i)
			{
				digest[(i * 4) + 0] = (uint8_t)((htonl(buffer[i]) & 0x000000FF));
				digest[(i * 4) + 1] = (uint8_t)((htonl(buffer[i]) & 0x0000FF00) >>  8);
				digest[(i * 4) + 2] = (uint8_t)((htonl(buffer[i]) & 0x00FF0000) >> 16);
				digest[(i * 4) + 3] = (uint8_t)((htonl(buffer[i]) & 0xFF000000) >> 24);
			}
			return (0) ;
		default:
			ft_fprintf(2, "print: unknown len\n");
			return (1);
	}
}

void    print_usage()
{
	ft_putstr_fd("help:\n\n", 2);
	ft_putstr_fd("Message Digest commands:\n", 2);
	ft_putstr_fd("md5\n", 2);
	ft_putstr_fd("sha256\n", 2);
	ft_putchar_fd('\n', 2);
}

void    print_input_digest(int opt, uint8_t *digest, const uint32_t *buffer, size_t len, char *str)
{
	if (set_digest(digest, buffer, len))
		return ;
	if (!(opt & e_p) && !(opt & e_q))
		ft_printf("(stdin)= ");
	else if (!(opt & e_q))
		ft_printf("(\"%s\")= ", str);
	for(unsigned int i = 0; i < len; ++i)
			put_hex(digest[i]);
	ft_putchar_fd('\n', 1);
}

void	print_digest(int opt, uint8_t *digest, const uint32_t *buffer, size_t len, char *str)
{
	if (set_digest(digest, buffer, len))
		return ;
	if (!(opt & e_r) && !(opt & e_q))
	{
		switch (len)
		{
			case MD5_DIGEST_LGTH:
				if (opt & e_file)
					ft_printf("MD5 (%s)= ", str);
				else
					ft_printf("MD5 (\"%s\")= ", str);
				break ;
			case SHA256_DIGEST_LGTH:
				if (opt & e_file)
					ft_printf("SHA256 (%s)= ", str);
				else
					ft_printf("SHA256 (\"%s\")= ", str);
				break ;
			default:
				ft_fprintf(2, "print: unknown len\n");
				return ;
		}
		for(unsigned int i = 0; i < len; ++i)
			put_hex(digest[i]);
	}
	else if (!(opt & e_q))
	{
		for(unsigned int i = 0; i < len; ++i)
			put_hex(digest[i]);
		if (opt & e_file)
			ft_printf(" %s", str);
		else
			ft_printf(" \"%s\"", str);
	}
	else
		for(unsigned int i = 0; i < len; ++i)
			put_hex(digest[i]);
	ft_putchar_fd('\n', 1);
}
