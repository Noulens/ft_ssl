//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

t_parsed	parse(int ac, char **av)
{
	if (ac < 2)
	{
		print_usage();
		exit(1);
	}
	for (int i = 0; g_parsed[i].cmd; i++)
	{
		if (!ft_strcmp(av[1], g_parsed[i].cmd))
			return (g_parsed[i]);
	}
	ft_putstr_fd("Invalid tool: ", STDERR_FILENO);
	ft_putstr_fd(av[1], STDERR_FILENO);
	ft_putchar_fd('\n', STDERR_FILENO);
	print_usage();
	exit(1);
}

int    md5parser(int ac, char **av)
{
	size_t	len;
	char	*stdinput = NULL;
	char	*file_list = NULL;
	char    *tmp = NULL;
	int 	options = 0;

	av += 2;
	if (ac < 1)
		exit (1);
	len = ft_ptrlen((const char **)av);
	while (len)
	{
		if (**av == '-')
		{
			++*av;
			while (**av)
			{
				switch (**av)
				{
					case 'p':
						options |= e_p;
						break;
					case 'q':
						options |= e_q;
						break;
					case 'r':
						options |= e_r;
						break;
					case 's':
						options |= e_s;
						break;
					default:
						fprintf(stderr, "ft_ssl: md5: invalid option -- \'%c\'\n", **av);
						exit(1);
				}
				++*av;
			}
		}
		else
		{
			break ;
		}
		len--;
		++av;
	}
	while (len--)
	{
		file_list = ft_append(file_list, *av);
		if (!file_list)
			error("check args: ", errno, TRUE);
		++av;
	}
	while ((tmp = get_next_line(STDIN_FILENO)))
	{
		stdinput = ft_append(stdinput, tmp);
		if (!stdinput)
		{
			free(file_list);
			error("check args: ", errno, TRUE);
		}
		free(tmp);
	}
	return (options);
}


