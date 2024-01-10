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
