/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 14:59:41 by banthony          #+#    #+#             */
/*   Updated: 2019/10/24 15:20:39 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

static size_t	salt_handler(t_des *des, uint8_t *entry, size_t size)
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

void			des_ecb_encode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	size_t		padd;
	char		*padded_input;
	size_t		i;

	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padd = 8 - (des->result_len % 8);
	padded_input = (char*)ft_memalloc(des->result_len + padd);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padd);
	ft_memcpy(padded_input, entry, des->result_len);
	ft_memset(padded_input + des->result_len, (int)padd, padd);
	i = 0;
	des->result_len += padd;
	while (i < des->result_len)
	{
		des_core(&padded_input[i], subkey, &(des->result[i]), CIPHER_ENCODE);
		i += 8;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des_ecb_decode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	size_t		i;

	i = 0;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	if (des->result_len % 8)
	{
		ft_putstr_fd("error3", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	des->result = (uint8_t*)ft_memalloc(des->result_len);
	while (i < des->result_len)
	{
		des_core(&entry[i], subkey, &(des->result[i]), CIPHER_DECODE);
		i += 8;
	}
	des->result_len = get_padding_to_remove(des->result, des->result_len);
}

void			des_cbc_encode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	(void)subkey;
	(void)size;
	(void)des;
	(void)entry;
}

void			des_cbc_decode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	(void)subkey;
	(void)size;
	(void)des;
	(void)entry;
}
