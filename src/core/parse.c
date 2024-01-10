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

void read_stdin(char *stdinput, t_opt *opt)
{
	char	*tmp = NULL;
	while ((tmp = get_next_line(STDIN_FILENO)))
	{
		if (!(stdinput = ft_append(stdinput, tmp)))
			error("read_stdin", errno, TRUE);
		free(tmp);
	}
	opt->stdinput = stdinput;
}

t_opt	*md5parser(int ac, char **av)
{
	size_t	len;
	char	*stdinput = NULL;
	char	*file_list = NULL;
	char    *tmp = NULL;
	t_opt	*opt = NULL;

	(void)tmp;
	if (!(opt = (t_opt *)malloc(sizeof(t_opt))))
		error("md5parser", errno, TRUE);
	if (ac == 2)
	{
		opt->flags = 0;
		opt->files = NULL;
		read_stdin(stdinput, opt);
		return (opt);
	}
	av += 2;
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
						opt->flags |= e_p;
						break;
					case 'q':
						opt->flags |= e_q;
						break;
					case 'r':
						opt->flags |= e_r;
						break;
					case 's':
						opt->flags |= e_s;
						break;
					default:
						ft_putstr_fd("ft_ssl: md5: invalid option -- \'", STDERR_FILENO);
						ft_putchar_fd(**av, STDERR_FILENO);
						ft_putstr_fd("\'\n", STDERR_FILENO);
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
		char	*p = NULL;
		while ((p = ft_strchr(*av, ' ')))
			*p = '_';
		file_list = ft_append(file_list, *av);
		if (!file_list)
			error("check args: ", errno, TRUE);
		file_list = ft_append(file_list, " ");
		if (!file_list)
			error("check args: ", errno, TRUE);
		++av;
	}
	opt->stdinput = NULL;
//	read_stdin(stdinput, opt);
	if (!(opt->files = ft_split(file_list, ' ')))
		error("md5parser", errno, TRUE);
	free(file_list);
	return (opt);
}


