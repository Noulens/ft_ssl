//
// Created by tnoulens on 1/10/24.
//

#include "libft.h"

char    *ft_append(char *old, char *new)
{
	int				len;
	register char	*ptr;
	char			*ret;
	register char	*oldptr;

	if ((old == NULL && new == NULL) || new == NULL)
		return (NULL);
	oldptr = old;
	if (!old)
		len = ft_strlen(new);
	else
		len = ft_strlen(oldptr) + ft_strlen(new);
	ret = (char *)malloc(len * sizeof(char) + 8);
	if (!ret)
		return (NULL);
	ft_bzero(ret, len + 8);
	ptr = ret;
	while (oldptr && *oldptr)
		*ptr++ = *oldptr++;
	while (*new)
		*ptr++ = *new++;
	*ptr = 0;
	free(old);
	return (ret);
}
