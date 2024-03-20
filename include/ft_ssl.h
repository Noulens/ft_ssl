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
# include <arpa/inet.h>
# include <emmintrin.h>
# include <tmmintrin.h>

# ifndef BUFFER_SIZE
# define BUFFER_SIZE 4096
# endif

void		*do_md5(void *to_digest);
void		*do_sha256(void *to_digest);
void		error(char *msg, int error_code, int must_exit);
void	   	*HashParser(int ac, char **av);
void		print_usage();
t_parsed	parse(int ac, char **av);
void		clean_opt_hash(t_hash *to_clean);
size_t		bitsToAdd(size_t len);
void		rotate_buffers(uint32_t *buffer, size_t len);
uint32_t	rotateRight(uint32_t x, uint32_t n);
uint32_t	rotateLeft(uint32_t x, uint32_t n);
void		splitInWords(uint32_t *X, const uint8_t *full_message);

/*
 * print function
 * */
void		print_digest(int opt, uint8_t *digest, const uint32_t *buffer, size_t len, char *str);
void		print_input_digest(int opt, uint8_t *digest, const uint32_t *buffer, size_t len, char *str);

/*
 * md5 functions
 */
uint32_t	F(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	G(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	H(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t	I(uint32_t X, uint32_t Y, uint32_t Z);
void		md5(t_MD5Context *ctx, char *s, size_t l);
void		MD5ctx_init(t_MD5Context *ctx);
void		md5append(t_MD5Context *ctx);
char		*md5_readinput(t_hash *to_digest, t_MD5Context *ctx, int fd);

/*
 * sha256 functions
 */
char		*sha256_readinput(t_hash *to_digest, t_sha256Context *ctx, int fd);
void		initSha256Ctx(t_sha256Context *ctx);
void		sha256(t_sha256Context *ctx, char *s, size_t len);
void		sha256append(t_sha256Context *ctx);

/*
 * global variable for toolbox
 */
static const t_parsed	g_parsed[] =
{
	{"md5", NULL, e_is_hash, HashParser, do_md5},
	{"sha256", NULL, e_is_hash, HashParser, do_sha256},
	{0},
};

#endif //FT_SSL_FT_SSL_H
