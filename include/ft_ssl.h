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

# define MD5_DIGEST_LGTH 16

typedef enum e_opt
{
	P = 0b00000001,
	Q = 0b00000010,
	R = 0b00000100,
	S = 0b00001000
}   t_opt;

typedef union u_word
{
	unsigned int w;
	unsigned char b[4];
}   t_word;

void    do_md5(const unsigned char *to_digest, size_t len, unsigned char *result);
void    error(char *msg, int error_code, int must_exit);
void    check_args(int ac, char **av, char **stdinput, char **file_list, int *options);

#endif //FT_SSL_FT_SSL_H
