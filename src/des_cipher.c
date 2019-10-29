/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 14:59:41 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:32:21 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

void			des_ecb_encode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	uint8_t		*padded_input;
	size_t		i;
	uint64_t	data;

	i = 0;
	des_padd(des, entry, size, &padded_input);
	while (i < des->result_len)
	{
		data = *(uint64_t*)(void*)&padded_input[i];
		data = swap_uint64(data);
		des_core(data, subkey, &(des->result[i]), CIPHER_ENCODE);
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
	uint64_t	data;

	i = 0;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	if (des->result_len % 8)
		ft_exit("Padd error", EXIT_FAILURE);
	des->result = (uint8_t*)ft_memalloc(des->result_len);
	while (i < des->result_len)
	{
		data = *(uint64_t*)(void*)&entry[i];
		data = swap_uint64(data);
		des_core(data, subkey, &(des->result[i]), CIPHER_DECODE);
		i += 8;
	}
	des->result_len = get_padding_to_remove(des->result, des->result_len);
}

void			des_cbc_encode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	uint8_t		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	vector;

	i = 0;
	des_padd(des, entry, size, &padded_input);
	hexastring_to_uint64(des->i_vector, &vector);
	while (i < des->result_len)
	{
		data = vector ^ swap_uint64(*(uint64_t*)(void*)&padded_input[i]);
		des_core(data, subkey, &(des->result[i]), CIPHER_ENCODE);
		vector = swap_uint64(*(uint64_t*)(void*)&des->result[i]);
		i += 8;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des_cbc_decode(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	size_t		i;
	uint64_t	data;
	uint64_t	vector;

	i = 0;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	if (des->result_len % 8)
		ft_exit("Padd error", EXIT_FAILURE);
	hexastring_to_uint64(des->i_vector, &vector);
	des->result = (uint8_t*)ft_memalloc(des->result_len);
	while (i < des->result_len)
	{
		data = swap_uint64(*(uint64_t*)(void*)&entry[i]);
		des_core(data, subkey, &(des->result[i]), CIPHER_DECODE);
		data = swap_uint64(*(uint64_t*)(void*)&des->result[i]) ^ vector;
		vector = swap_uint64(*(uint64_t*)(void*)&entry[i]);
		data = swap_uint64(data);
		ft_memcpy(&des->result[i], &data, 8);
		i += 8;
	}
	des->result_len = get_padding_to_remove(des->result, des->result_len);
}
