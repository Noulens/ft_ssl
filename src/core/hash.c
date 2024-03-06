//
// Created by tnoulens on 1/11/24.
//

#include "ft_ssl.h"

static void md5_readinput(t_md5 *to_digest, t_MD5Context *ctx, int fd)
{
	char    buff[BUFFER_SIZE + 1];
	ssize_t nb_read;

	MD5ctx_init(ctx);
	ft_memset(buff, 0, BUFFER_SIZE + 1);
	while ((nb_read = read(fd, buff, BUFFER_SIZE)) > 0)
	{
		buff[nb_read] = 0;
		md5(ctx, buff, to_digest->flags, nb_read);
		ft_memset(buff, 0, BUFFER_SIZE + 1);
	}
	if (nb_read == -1)
	{
		error("ft_ssl: read: ", errno, FALSE);
		clean_opt_md5(to_digest);
		exit(1);
	}
	else
	{
		md5append(ctx, to_digest->flags);
		print_result_md5(to_digest, ctx);
	}
}

void    *do_md5(void *data)
{
	t_md5			*to_digest = (t_md5 *)data;
	t_MD5Context	ctx = {0};

	if ((to_digest->flags & e_one_op) || (to_digest->flags & e_p) || (to_digest->flags & e_q))
	{
		md5_readinput(to_digest, &ctx, STDIN_FILENO);
		if (to_digest->flags & e_one_op)
		{
			clean_opt_md5(to_digest);
			return ("success one op");
		}
	}
	if (to_digest->str)
	{
		MD5ctx_init(&ctx);
		md5(&ctx, to_digest->str, to_digest->flags, ft_strlen(to_digest->str));
		md5append(&ctx, to_digest->flags);
		print_result_md5(to_digest, &ctx);
	}
	while (to_digest->files && *to_digest->files)
	{
		int fd = open(*to_digest->files, O_RDONLY);

		if (fd == -1)
			ft_fprintf(2, "ft_ssl: md5: %s: No such file or directory\n", *to_digest->files);
		else
		{
			md5_readinput(to_digest, &ctx, fd);
			close(fd);
		}
		to_digest->files++;
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
