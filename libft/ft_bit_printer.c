//
// Created by tnoulens on 3/6/24.
//

#include "libft.h"

static void bit_printer(uint8_t c)
{
	int	bit_comp;

	bit_comp = 0b10000000;
	while (bit_comp)
	{
		if (bit_comp & c)
			ft_putchar_fd('1', 1);
		else
			ft_putchar_fd('0', 1);
		bit_comp >>= 1;
	}
}

void	print_bits(uint8_t *full, size_t len)
{
	size_t		i = 0;
	uint8_t		*ptr = full;

	while (i < len)
	{
		bit_printer(ptr[i]);
		i++;
		if (i % 4 == 0)
			ft_putchar_fd('\n', 1);
		else
			ft_putchar_fd(' ', 1);
	}
}
