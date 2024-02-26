//
// Created by tnoulens on 1/11/24.
//

#include "ft_ssl.h"

void    *do_md5(void *data)
{
	t_md5			*to_digest = (t_md5 *)data;
	t_MD5Context	ctx = {0};

	if (to_digest->flags & e_one_op)
	{
		MD5ctx_init(&ctx);
		md5(&ctx, to_digest->stdinput, to_digest->flags);
		print_result_md5(to_digest, &ctx);
		clean_opt_md5(to_digest);
		return ("success one op");
	}
	if (to_digest->str)
	{
		MD5ctx_init(&ctx);
		md5(&ctx, to_digest->str, to_digest->flags);
		print_result_md5(to_digest, &ctx);
	}
	printf("List of files:\n");
	while (to_digest->files && *to_digest->files)
	{
		
	}
	clean_opt_md5(to_digest);
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
