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
	size_t bits = len * 8;
	size_t bits_to_add;

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

void	rotate_buffers(uint32_t *buffer, size_t len)
{
	uint32_t	tmp = 0;

	tmp = buffer[len - 1];
	for (int rotb = len - 1; rotb > 0; rotb--)
		buffer[rotb] = buffer[rotb - 1];
	buffer[a] = tmp;
}

void	splitInWords(int flags, uint32_t *X, const uint8_t *full_message)
{
	(void)flags;
	for (size_t j = 0; j < 16; j++)
		X[j] |= full_message[j * 4]
				| (full_message[j * 4 + 1] << 8)
				| (full_message[j * 4 + 2] << 16)
				| (full_message[j * 4 + 3] << 24);
}

uint32_t	mod_add(uint32_t a, uint32_t b)
{
	uint32_t	sum;

	sum = a + b;
	if ( sum < a || sum < b)
		sum -= UINT32_MAX;
	return (sum);
}
