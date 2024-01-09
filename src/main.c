//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

int main(int ac, char **av)
{
	char        *args = NULL;
	char        *file_list = NULL;
	char        **list = NULL;
	int         options = 0;

	check_args(ac, av, &args, &file_list, &options);
	printf("here: %s\n", file_list);
	list = ft_split(file_list, ' ');
	free(file_list);
	for (int i = 0; list[i]; i++)
		printf("%s\n", list[i]);
	ft_free_split(list);
	printf("here2: %s\n", args);
	return (0);
}
