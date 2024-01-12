//
// Created by tnoulens on 1/10/24.
//

#ifndef FT_SSL_STRUCT_H
# define FT_SSL_STRUCT_H

typedef enum e_flags
{
	e_p = 0b00000001,
	e_q = 0b00000010,
	e_r = 0b00000100,
	e_s = 0b00001000
}   t_flags;

typedef enum e_operation
{
	e_is_cipher = 0b0,
	e_is_hash = 0b00000001
}   t_operation;

typedef union u_word
{
	unsigned int w;
	unsigned char b[4];
}   t_word;

typedef union u_dword
{
	unsigned long dw;
	unsigned char b[8];
}   t_dword;

typedef struct s_opt_md5
{
	int		flags;
	char	*stdinput;
	char 	*str;
	char 	**files;
}	t_md5;

typedef struct s_opt_sha256
{
	int		flags;
	char	*stdinput;
	char 	*str;
	char 	**files;
}	t_sha256;

typedef void	*(*t_func_parse)(int ac, char **av);
typedef void	*(*t_func_do)(void *);

typedef struct s_parsed
{
	const char      *cmd;
	void			*opt;
	t_operation     operation_type;
	t_func_parse    parse_ptr;
	t_func_do       do_ptr;
}   t_parsed;

#endif //FT_SSL_STRUCT_H
