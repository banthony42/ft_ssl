/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 15:03:59 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:30:04 by banthony         ###   ########.fr       */
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

size_t	salt_handler(t_des *des, uint8_t *entry, size_t size)
{
	uint8_t		*tmp;
	uint64_t	salt;

	tmp = des->result;
	des->result = (uint8_t*)ft_memalloc(des->result_len + 16);
	ft_memcpy(des->result, "Salted__", 8);
	hexastring_to_uint64(des->salt, &salt);
	ft_memcpy(des->result + 8, &salt, 8);
	ft_memcpy(des->result + 16, tmp, des->result_len);
	des->result_len += 16;
	ft_memdel((void**)&tmp);
	(void)entry;
	(void)size;
	return (0);
}

void	des_padd(t_des *des, char *entry, size_t size, uint8_t **padded)
{
	size_t padding;

	*padded = NULL;
	if (!des || !entry || !padded)
		ft_exit("Fatal error while padding.", EXIT_FAILURE);
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padding = 8 - (des->result_len % 8);
	*padded = (uint8_t*)ft_memalloc(des->result_len + padding);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padding);
	ft_memcpy(*padded, entry, des->result_len);
	ft_memset(*padded + des->result_len, (int)padding, padding);
	des->result_len += padding;
}

void	des_padd_without_scheme(t_des *des, char *entry, size_t size,
											uint8_t **padded)
{
	size_t padding;

	if (!des || !entry || !padded)
		ft_exit("Fatal error while padding.", EXIT_FAILURE);
	*padded = NULL;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padding = 8 - (des->result_len % 8);
	*padded = (uint8_t*)ft_memalloc(des->result_len + padding);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padding);
	ft_memcpy(*padded, entry, des->result_len);
}

size_t	get_padding_to_remove(uint8_t *decipher, size_t len)
{
	uint8_t		*ptr;
	size_t		i;
	uint32_t	value;
	uint32_t	last_value;
	uint32_t	padd_len;

	ptr = (unsigned char*)decipher + len;
	padd_len = 0;
	last_value = 0;
	i = *(ptr - 1);
	while (i && i < len)
	{
		value = *(ptr - i);
		if (last_value && value != last_value)
		{
			if (last_value != padd_len)
				ft_exit("padding corruption detected.", EXIT_FAILURE);
			else
				break ;
		}
		last_value = value;
		padd_len++;
		i--;
	}
	return (len - padd_len);
}
