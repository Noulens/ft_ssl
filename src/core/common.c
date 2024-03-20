//
// Created by tnoulens on 3/11/24.
//

#include "ft_ssl.h"

uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32 - n));
}

uint32_t rotateRight(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
}

size_t bitsToAdd(size_t len)
{
	size_t	bits = len * 8;
	size_t	bits_to_add;

	if (!len)
		bits_to_add = 448;
	else
	{
		bits_to_add = ((bits + 511) - ((bits + 511) % 512)) - len * 8;
		if (bits_to_add % 512 == 0)
			bits_to_add = 448;
		else
		{
			if (bits_to_add <= 64)
				bits_to_add = 448 + bits_to_add;
			else
				bits_to_add = bits_to_add - 64;
		}
	}
	return bits_to_add;
}
