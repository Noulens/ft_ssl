//
// Created by tnoulens on 1/11/24.
//

#include "ft_ssl.h"

void    *do_md5(void *data)
{
	t_md5	*to_digest = (t_md5 *)data;
	char 	*res = NULL;

	if (to_digest->flags & e_one_op)
	{
		// TODO: remove this printf
		ft_printf("%s\n", to_digest->stdinput);
		md5(to_digest->stdinput, to_digest->flags);
		print_result_md5(to_digest, res);
		return ("success one op");
	}
	if (to_digest->str)
		printf("STR opt: %s\n", to_digest->str);
	if (to_digest->stdinput)
		printf("STDIN: %s\n", to_digest->stdinput);
	printf("List of files:\n");
	while (to_digest->files && *to_digest->files)
		printf("%s\n", *to_digest->files++);

	// TODO: put md5 hash here
	return ("success");
}

void    *do_sha256(void *data)
{
	t_sha256	*to_digest = (t_sha256 *)data;

	if (to_digest->str)
		printf("STR opt: %s\n", to_digest->str);
	if (to_digest->stdinput)
		printf("STDIN: %s\n", to_digest->stdinput);
	printf("List of files:\n");
	while (to_digest->files && *to_digest->files)
		printf("%s\n", *to_digest->files++);
	// TODO: put sha256 has here
	return ("success");
}
