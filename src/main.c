//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

int main(int ac, char **av)
{
	t_parsed	parser;

	parser = parse(ac, av);
	parser.opt = parser.parse_ptr(ac, av);
	if (((t_opt_md5 *)parser.opt)->str)
		printf("STR opt: %s\n", ((t_opt_md5 *)parser.opt)->str);
	if (((t_opt_md5 *)parser.opt)->stdinput)
		printf("STDIN: %s\n", ((t_opt_md5 *)parser.opt)->stdinput);
	printf("List of files:\n");
	while (((t_opt_md5 *)parser.opt)->files && *((t_opt_md5 *)parser.opt)->files)
		printf("%s\n", *((t_opt_md5 *)parser.opt)->files++);

	clean_opt(((t_opt_md5 *)parser.opt));
	return (0);
}
