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

void		*do_md5(void *to_digest);
void		*do_sha256(void *to_digest);
void		error(char *msg, int error_code, int must_exit);
void	   	*md5parser(int ac, char **av);
void		*sha256parser(int ac, char **av);
void		print_usage();
void		read_stdin(char **stdinput);
t_parsed	parse(int ac, char **av);
void		clean_opt_md5(t_md5 *to_clean);
void		clean_opt_sha256(t_sha256 *to_clean);
void		print_result_md5(t_md5 *opt, char *res);
uint32_t	readWord(uint32_t data, int opt);
uint64_t	readXWord(uint64_t data, int opt);
void		reverseEndiannessArray32(uint32_t *array, size_t size);
void		reverseEndiannessArray64(uint64_t *array, size_t size);
/*
 * md5 functions
 */
uint32_t	F(t_word X, t_word Y, t_word Z);
uint32_t	G(t_word X, t_word Y, t_word Z);
uint32_t	H(t_word X, t_word Y, t_word Z);
uint32_t	I(t_word X, t_word Y, t_word Z);
uint32_t	rotateLeft(uint32_t x, uint32_t n);
void		initialize_ABCD(t_word *A, t_word *B, t_word *C, t_word *D);
char		*md5(char *s, int flags);

/*
 * global variable for toolbox
 */
static const t_parsed	g_parsed[] =
{
	{"md5", NULL, e_is_hash, md5parser, do_md5},
	{"sha256", NULL, e_is_hash, sha256parser, do_sha256},
	{0},
};

#endif //FT_SSL_FT_SSL_H
