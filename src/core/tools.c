//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

void    error(char *msg, int error_code, int must_exit)
{
	if (error_code != -1)
	{
		ft_putstr_fd("ft_ssl: ", STDERR_FILENO);
		ft_putstr_fd(msg, STDERR_FILENO);
		ft_putstr_fd(strerror(error_code), STDERR_FILENO);
		ft_putchar_fd('\n', STDERR_FILENO);
	}
	else
	{
		ft_putstr_fd("ft_ssl: ", STDERR_FILENO);
		ft_putstr_fd(msg, STDERR_FILENO);
		ft_putchar_fd('\n', STDERR_FILENO);
	}
	if (must_exit == TRUE)
	{
		exit(EXIT_FAILURE);
	}
}

void    print_usage()
{
	ft_putstr_fd("help:\n\n", STDERR_FILENO);
	ft_putstr_fd("Message Digest commands:\n", STDERR_FILENO);
	ft_putstr_fd("md5\n", STDERR_FILENO);
	ft_putstr_fd("sha256\n", STDERR_FILENO);
	ft_putchar_fd('\n', STDERR_FILENO);
}
