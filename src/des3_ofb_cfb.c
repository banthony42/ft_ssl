/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des3_ofb_cfb.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:32:26 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:32:37 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

void			des_ofb_cipher(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	uint8_t		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	out;

	i = 0;
	des_padd_without_scheme(des, entry, size, &padded_input);
	hexastring_to_uint64(des->i_vector, &data);
	while (i < des->result_len)
	{
		des_core(data, subkey, (uint8_t*)&out, CIPHER_ENCODE);
		data = (*(uint64_t*)(void*)&padded_input[i]) ^ out;
		ft_memcpy(&des->result[i], &data, 8);
		data = swap_uint64(out);
		i += 8;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des_cfb_cipher(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	uint8_t		*padded;
	size_t		i;
	uint64_t	data;
	uint64_t	out;

	i = 0;
	des_padd_without_scheme(des, entry, size, &padded);
	hexastring_to_uint64(des->i_vector, &data);
	while (i < des->result_len)
	{
		des_core(data, subkey, (uint8_t*)&out, CIPHER_ENCODE);
		data = swap_uint64(swap_uint64(*(uint64_t*)(void*)&padded[i])
				^ swap_uint64(out));
		ft_memcpy(&des->result[i], &data, 8);
		data = (des->cipher_mode == CIPHER_DECODE) ?
			swap_uint64(*(uint64_t*)(void*)&padded[i]) : swap_uint64(data);
		i += 8;
	}
	ft_memdel((void**)&padded);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des3_encode(t_des *des, char *entry, size_t size,
								t_des3_subkey subkey)
{
	uint8_t		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	out;
	uint64_t	vector;

	i = 0;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	des_padd(des, entry, size, &padded_input);
	hexastring_to_uint64(des->i_vector, &vector);
	while (i < des->result_len)
	{
		data = *(uint64_t*)(void*)&padded_input[i];
		data = vector ^ swap_uint64(data);
		des_core(data, subkey.s1, (uint8_t*)&out, CIPHER_ENCODE);
		des_core(swap_uint64(out), subkey.s2, (uint8_t*)&out, CIPHER_DECODE);
		data = swap_uint64(out) ^ vector;
		des_core(vector ^ data, subkey.s3, (uint8_t*)&out, CIPHER_ENCODE);
		vector = swap_uint64(out);
		ft_memcpy(&des->result[i], &out, 8);
		i += 8;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des3_decode(t_des *des, char *entry, size_t size,
								t_des3_subkey subkey)
{
	size_t		i;
	uint64_t	data;
	uint64_t	vector;
	uint64_t	out;

	i = 0;
	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	if (des->result_len % 8)
		ft_exit("Padd error", EXIT_FAILURE);
	hexastring_to_uint64(des->i_vector, &vector);
	des->result = (uint8_t*)ft_memalloc(des->result_len);
	while (i < des->result_len)
	{
		des_core(swap_uint64(*(uint64_t*)(void*)&entry[i]), subkey.s3,
					(uint8_t*)&out, CIPHER_DECODE);
		data = vector ^ (swap_uint64(out) ^ vector);
		des_core(data, subkey.s2, (uint8_t*)&out, CIPHER_ENCODE);
		des_core(swap_uint64(out), subkey.s1, (uint8_t*)&out, CIPHER_DECODE);
		data = swap_uint64(out) ^ vector;
		data = swap_uint64(data);
		ft_memcpy(&des->result[i], &data, 8);
		vector = swap_uint64(*(uint64_t*)(void*)&entry[i]);
		i += 8;
	}
	des->result_len = get_padding_to_remove(des->result, des->result_len);
}
