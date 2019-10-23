/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 15:03:59 by banthony          #+#    #+#             */
/*   Updated: 2019/10/23 16:42:19 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

static const char	g_convert[16] =
{
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

void	hexastring_to_uint64(char *str, uint64_t *key)
{
	char	c;
	size_t	i;
	size_t	len;

	i = 0;
	c = 0;
	*key = 0;
	len = ft_strlen(str);
	while (i < 16)
	{
		if (i >= len)
			c = 0;
		else if (ft_toupper(str[i]) >= 48 && ft_toupper(str[i]) <= 57)
			c = g_convert[(ft_toupper(str[i]) - 48)];
		else if (ft_toupper(str[i]) >= 65 && ft_toupper(str[i]) <= 70)
			c = g_convert[(ft_toupper(str[i]) - 55)];
		*key = (*key << 4) | (uint64_t)c;
		i++;
	}
}

size_t	get_padding_to_remove(uint8_t *decipher, size_t len)
{
	uint8_t	last_value;
	uint8_t *ptr;
	size_t	padding_size;

	ptr = decipher + len;
	padding_size = *(ptr - 1);
	last_value = 0;
	while (padding_size)
	{
		if (last_value != 0 && last_value != *(ptr - padding_size))
		{
			ft_putendl("error end padding check");
			exit(EXIT_FAILURE);
		}
		len--;
		padding_size--;
	}
	return (len);
}
