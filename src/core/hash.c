//
// Created by tnoulens on 1/11/24.
//

#include "ft_ssl.h"

void    *do_md5(void *data)
{
	t_md5	*to_digest = (t_md5 *)data;

	if (to_digest->str)
		printf("STR opt: %s\n", to_digest->str);
	if (to_digest->stdinput)
		printf("STDIN: %s\n", to_digest->stdinput);
	printf("List of files:\n");
	while (to_digest->files && *to_digest->files)
		printf("%s\n", *to_digest->files++);
	return ("success");
}
