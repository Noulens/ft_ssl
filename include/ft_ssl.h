//
// Created by tnoulens on 1/8/24.
//

#ifndef FT_SSL_FT_SSL_H
# define FT_SSL_FT_SSL_H

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <fcntl.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <string.h>
# include <errno.h>
# include "libft.h"
# include "struct.h"

# define MD5_DIGEST_LGTH 16

void		*do_md5(void *to_digest, size_t len);
void		error(char *msg, int error_code, int must_exit);
t_opt	   	*md5parser(int ac, char **av);
void		print_usage();
t_parsed	parse(int ac, char **av);
void		clean_opt(t_opt *to_clean);
void		print_result(t_opt opt, char *res);

static const t_parsed	g_parsed[] =
{
	{"md5", NULL, e_is_hash, md5parser, do_md5},
	{"sha256", NULL, e_is_hash, NULL, do_md5},
	{0},
};

#endif //FT_SSL_FT_SSL_H
