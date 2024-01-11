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
		if (!ft_strcmp(av[1], g_parsed[i].cmd))
			return (g_parsed[i]);
	ft_putstr_fd("Invalid tool: ", STDERR_FILENO);
	ft_putstr_fd(av[1], STDERR_FILENO);
	ft_putchar_fd('\n', STDERR_FILENO);
	print_usage();
	exit(1);
}

void read_stdin(char *stdinput, t_opt_md5 *opt)
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

void exit_clean_opt_s(char *const *av, t_opt_md5 *opt)
{
	ft_putstr_fd("ft_ssl: md5: invalid string -- \"", STDERR_FILENO);
	ft_putstr_fd((*av + 1), STDERR_FILENO);
	ft_putstr_fd("\"\n", STDERR_FILENO);
	clean_opt(opt);
	exit(1);
}

void	*md5parser(int ac, char **av)
{
	int		len;
	char	*stdinput = NULL;
	char    *tmp = NULL;
	t_opt_md5	*opt = NULL;

	(void)tmp;
	if (!(opt = (t_opt_md5 *)malloc(sizeof(t_opt_md5))))
		error("md5parser", errno, TRUE);
	opt->flags = 0;
	opt->stdinput = NULL;
	opt->str = NULL;
	opt->files = NULL;
	if (ac == 2)
	{
		read_stdin(stdinput, opt);
		return (opt);
	}
	av += 2;
	len = ft_ptrlen((const char **)av);
	while (len > 0)
	{
		if (**av == '-' && !(opt->flags & e_s))
		{
			++*av;
			while (*av && **av && !(opt->flags & e_s))
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
						if ((*(*av + 1)) != 0 || *(av + 1) == 0)
							exit_clean_opt_s(av, opt);
						else
						{
							++av;
							len--;
							if (!(opt->str = ft_strdup(*av)))
							{
								clean_opt(opt);
								error("md5parser", errno, TRUE);
							}
						}
						opt->flags |= e_s;
						break;
					default:
						ft_putstr_fd("ft_ssl: md5: invalid option -- \'", STDERR_FILENO);
						ft_putchar_fd(**av, STDERR_FILENO);
						ft_putstr_fd("\'\n", STDERR_FILENO);
						clean_opt(opt);
						exit(1);
				}
				if (*av && !(opt->flags & e_s))
					++*av;
			}
		}
		else
			break ;
		len--;
		++av;
	}
	if (len > 0)
		opt->files = av;
	if ((opt->flags & e_p) || (opt->flags & e_q))
		read_stdin(stdinput, opt);
	return (opt);
}


