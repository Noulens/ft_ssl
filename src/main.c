//
// Created by tnoulens on 1/8/24.
//

#include "ft_ssl.h"

int main(int ac, char **av)
{
	t_parsed	parser;

	parser = parse(ac, av);
	parser.opt = parser.parse_ptr(ac, av);
	parser.do_ptr((void *)parser.opt);
	return (0);
}
