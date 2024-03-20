//
// Created by tnoulens on 1/11/24.
//

#include "ft_ssl.h"

void    *do_md5(void *data)
{
	t_hash			*to_digest = (t_hash *)data;
	t_MD5Context	ctx = {0};

	if ((to_digest->flags & e_one_op) || (to_digest->flags & e_p) || (to_digest->flags & e_q) || (to_digest->flags & e_r))
	{
		md5_readinput(to_digest, &ctx, STDIN_FILENO);
		print_input_digest(to_digest->flags, ctx.digest, ctx.buffer, MD5_DIGEST_LGTH, NULL);
		if (to_digest->flags & e_one_op)
		{
			clean_opt_hash(to_digest);
			return ("success one op");
		}
	}
	if (to_digest->str)
	{
		MD5ctx_init(&ctx);
		md5(&ctx, to_digest->str, ft_strlen(to_digest->str));
		md5append(&ctx);
		print_digest(to_digest->flags, ctx.digest, ctx.buffer, MD5_DIGEST_LGTH, to_digest->str);
	}
	while (to_digest->files && *to_digest->files)
	{
		int fd = open(*to_digest->files, O_RDONLY);

		if (fd == -1)
			ft_fprintf(1, "ft_ssl: md5: %s: No such file or directory\n", *to_digest->files);
		else
		{
			to_digest->flags |= e_file;
			md5_readinput(to_digest, &ctx, fd);
			print_digest(to_digest->flags, ctx.digest, ctx.buffer, MD5_DIGEST_LGTH, *to_digest->files);
			close(fd);
		}
		to_digest->files++;
	}
	clean_opt_hash(to_digest);
	return ("success md5");
}

void    *do_sha256(void *data)
{
	t_hash			*to_digest = (t_hash *)data;
	t_sha256Context	ctx = {0};

	if ((to_digest->flags & e_one_op) || (to_digest->flags & e_p) || (to_digest->flags & e_q))
	{
		char *str = sha256_readinput(to_digest, &ctx, STDIN_FILENO);
		print_input_digest(to_digest->flags, ctx.digest, ctx.buffer, SHA256_DIGEST_LGTH, str);
		free(str);
		if (to_digest->flags & e_one_op)
		{
			clean_opt_hash(to_digest);
			return ("success one op");
		}
	}
	if (to_digest->str)
	{
		initSha256Ctx(&ctx, to_digest->flags);
		sha256(&ctx, to_digest->str, ft_strlen(to_digest->str));
		sha256append(&ctx);
		print_digest(to_digest->flags, ctx.digest, ctx.buffer, SHA256_DIGEST_LGTH, to_digest->str);
	}
	while (to_digest->files && *to_digest->files)
	{
		int fd = open(*to_digest->files, O_RDONLY);

		if (fd == -1)
			ft_fprintf(1, "ft_ssl: md5: %s: No such file or directory\n", *to_digest->files);
		else
		{
			to_digest->flags |= e_file;
			sha256_readinput(to_digest, &ctx, fd);
			print_digest(to_digest->flags, ctx.digest, ctx.buffer, SHA256_DIGEST_LGTH, *to_digest->files);
			close(fd);
		}
		to_digest->files++;
	}
	clean_opt_hash(to_digest);
	return ("success sha256");
}
