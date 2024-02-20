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

void	print_result_md5(t_md5 *opt, char *res)
{
	(void)opt;
	ft_putstr_fd("(stdin)= ", 1);
	ft_putstr_fd(res, 1);
}
