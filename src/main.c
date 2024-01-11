//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

int main(int ac, char **av)
{
	t_parsed	parser;

	parser = parse(ac, av);
	parser.opt = parser.parse_ptr(ac, av);
	if (parser.opt->str)
		printf("STR opt: %s\n", parser.opt->str);
	if (parser.opt->stdinput)
		printf("STDIN: %s\n", parser.opt->stdinput);
	printf("List of files:\n");
	while (parser.opt->files && *parser.opt->files)
		printf("%s\n", *parser.opt->files++);
	clean_opt(parser.opt);
	return (0);
}
