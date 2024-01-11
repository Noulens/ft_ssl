//
// Created by tnoulens on 1/10/24.
//

#include "ft_ssl.h"

void    print_usage()
{
	ft_putstr_fd("help:\n\n", STDERR_FILENO);
	ft_putstr_fd("Message Digest commands:\n", STDERR_FILENO);
	ft_putstr_fd("md5\n", STDERR_FILENO);
	ft_putstr_fd("sha256\n", STDERR_FILENO);
	ft_putchar_fd('\n', STDERR_FILENO);
}

void	print_result(t_opt_md5 opt, char *res)
{
	(void)opt;
	(void)res;
	ft_putstr_fd("(stdin)= ", STDIN_FILENO);
	ft_putstr_fd(res, STDIN_FILENO);
}
