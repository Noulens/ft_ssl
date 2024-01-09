//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

static char *ft_append(char *old, char *new)
{
	int				len;
	register char	*ptr;
	char			*ret;
	register char	*oldptr;

	if ((old == NULL && new == NULL) || new == NULL)
		return (NULL);
	oldptr = old;
	if (!old)
		len = ft_strlenb(new);
	else
		len = ft_strlenb(oldptr) + ft_strlenb(new);
	ret = (char *)malloc(len * sizeof(char) + 8);
	if (!ret)
		return (NULL);
	ft_bzero(ret, len + 8);
	ptr = ret;
	while (oldptr && *oldptr)
		*ptr++ = *oldptr++;
	*ptr++ = ' ';
	while (*new)
		*ptr++ = *new++;
	*ptr = 0;
	free(old);
	return (ret);
}

void    check_args(int ac, char **av, char **stdinput, char **file_list, int *options)
{
	size_t  len;
	(void)stdinput;
	char    *tmp = NULL;

	++av;
	if (ac < 3)
	{
		error("usage error", -1, TRUE);
		return ;
	}
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
						*options |= P;
						break;
					case 'q':
						*options |= Q;
						break;
					case 'r':
						*options |= R;
						break;
					case 's':
						*options |= S;
						break;
					default:
						fprintf(stderr, "ft_ssl: invalid option -- \'%c\'\n", **av);
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
		*file_list = ft_append(*file_list, *av);
		if (!*file_list)
			error("check args: ", errno, TRUE);
		++av;
	}
	char test[1];
	if (read(STDIN_FILENO, test, 0) != -1)
	{
		printf("here read\n");
		if (errno == EWOULDBLOCK)
		{
			printf("would block\n");
			return;
		}
		while ((tmp = get_next_line(STDIN_FILENO)))
		{
			*stdinput = ft_strjoin(*stdinput, tmp);
			if (!*stdinput)
			{
				free(*file_list);
				error("check args: ", errno, TRUE);
			}
			free(tmp);
		}
	}
}


