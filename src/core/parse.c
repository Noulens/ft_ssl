//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

t_parsed parse(int ac, char **av)
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

void *HashParser(int ac, char **av)
{
	size_t			len;
	t_hash 			*opt = NULL;

	if (!(opt = (t_hash *)malloc(sizeof(t_hash))))
		error("hash parser", errno, TRUE);
	opt->flags = 0;
	opt->str = NULL;
	opt->files = NULL;
	av += 2;
	len = ft_ptrlen((const char **) av);
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
						{
							ft_putstr_fd("ft_ssl: hash: invalid string -- \"", STDERR_FILENO);
							ft_putstr_fd((*av + 1), STDERR_FILENO);
							ft_putstr_fd("\"\n", STDERR_FILENO);
							clean_opt_hash(opt);
							exit(1);
						}
						else
						{
							++av;
							len--;
							if (!(opt->str = ft_strdup(*av)))
							{
								clean_opt_hash(opt);
								error("hash parser", errno, TRUE);
							}
						}
						opt->flags |= e_s;
						break;
					default:
						ft_putstr_fd("ft_ssl: hash: invalid option -- \'", STDERR_FILENO);
						ft_putchar_fd(**av, STDERR_FILENO);
						ft_putstr_fd("\'\n", STDERR_FILENO);
						clean_opt_hash(opt);
						exit(1);
				}
				if (*av && !(opt->flags & e_s))
					++*av;
			}
		}
		else
			break;
		len--;
		++av;
	}
	if (len > 0)
		opt->files = av;
	if ((!opt->files && !opt->str) || ac == 2)
		opt->flags |= e_one_op;
	return (opt);
}
