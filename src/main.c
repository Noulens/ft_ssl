//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

int main(int ac, char **av)
{
	t_parsed	parser;

	parser = parse(ac, av);
	parser.opt = parser.parse_ptr(ac, av);
	if (parser.opt->stdinput)
		printf("%s\n", parser.opt->stdinput);
	for (int i = 0; parser.opt->files[i]; i++)
		printf("%s\n", parser.opt->files[i]);
	clean(&parser);
	return (0);
}
