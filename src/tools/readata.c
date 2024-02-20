//
// Created by tnoulens on 2/20/24.
//

#include "ft_ssl.h"

static inline void reverseEndian(void *data, size_t size)
{
	switch (size)
	{
		case sizeof(uint32_t):
		{
			uint32_t *x = (uint32_t *)data;
			*x = ((*x >> 24) | ((*x << 8) & 0x00ff0000) | ((*x >> 8) & 0x0000ff00) | (*x << 24));
			return;
		}
		case sizeof(uint64_t):
		{
			uint64_t *y = (uint64_t *)data;
			*y = ((*y >> 56) |
				  ((*y << 40) & 0x00ff000000000000) |
				  ((*y << 24) & 0x0000ff0000000000) |
				  ((*y << 8)  & 0x000000ff00000000) |
				  ((*y >> 8)  & 0x00000000ff000000) |
				  ((*y >> 24) & 0x0000000000ff0000) |
				  ((*y >> 40) & 0x000000000000ff00) |
				  (*y << 56));
			return;
		}
		default:
			write(2, "Unknown size\n", 14);
			return ;
	}
}

inline void reverseEndiannessArray32(uint32_t *array, size_t size)
{
	for (size_t i = 0; i < size - 1; ++i) {
		reverseEndian(&array[i], sizeof(uint32_t));
	}
}

inline void reverseEndiannessArray64(uint64_t *array, size_t size)
{
	for (size_t i = 0; i < size - 1; ++i) {
		reverseEndian(&array[i], sizeof(uint64_t));
	}
}

inline uint32_t readWord(const uint32_t data, const int opt)
{
	uint32_t res = data;
	if (!(opt & e_little))
		reverseEndian(&res, sizeof(uint32_t));
	return res;
}

inline uint64_t readXWord(const uint64_t data, const int opt)
{
	uint64_t res = data;
	if (!(opt & e_little))
		reverseEndian(&res, sizeof(uint64_t));
	return res;
}

