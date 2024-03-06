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

# ifndef BUFFER_SIZE
# define BUFFER_SIZE 4096
# endif

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
uint32_t	readWord(uint32_t data, int opt);
uint64_t	readXWord(uint64_t data, int opt);
void		reverseEndiannessArray32(uint32_t *array, size_t size);
void		reverseEndiannessArray64(uint64_t *array, size_t size);
/*
 * md5 functions
 */
uint32_t	F(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	G(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	H(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	I(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	rotateLeft(uint32_t x, uint32_t n);
void		initialize_ABCD(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);
void		md5(t_MD5Context *ctx, char *s, int flags, size_t l);
void		MD5ctx_init(t_MD5Context *ctx);
void		md5append(t_MD5Context *ctx, int flags);
void		print_result_md5(t_md5 *opt, t_MD5Context *ctx);
void        print_full_message(uint8_t *full, size_t len);

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
