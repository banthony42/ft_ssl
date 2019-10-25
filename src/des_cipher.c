/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 14:59:41 by banthony          #+#    #+#             */
/*   Updated: 2019/10/25 17:18:57 by banthony         ###   ########.fr       */
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
	uint64_t	data;

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
	{
		ft_putstr_fd("error3", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
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
	size_t		padd;
	char		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	vector;

	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padd = 8 - (des->result_len % 8);
	padded_input = (char*)ft_memalloc(des->result_len + padd);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padd);
	ft_memcpy(padded_input, entry, des->result_len);
	ft_memset(padded_input + des->result_len, (int)padd, padd);
	i = 0;
	des->result_len += padd;
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
	{
		ft_putstr_fd("error3", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
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

void			des_ofb_cipher(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	size_t		padd;
	char		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	vector;

	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padd = 8 - (des->result_len % 8);
	padded_input = (char*)ft_memalloc(des->result_len + padd);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padd);
	ft_memcpy(padded_input, entry, des->result_len);
	i = 0;
	hexastring_to_uint64(des->i_vector, &vector);
	uint64_t out;
	while (i < des->result_len)
	{
		data = vector;
		des_core(data, subkey, (uint8_t*)&out, CIPHER_ENCODE);
		vector = swap_uint64(out);
		data = (*(uint64_t*)(void*)&padded_input[i]) ^ out;
		ft_memcpy(&des->result[i], &data, 8);
		i += 8;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}

void			des_cfb_cipher(t_des *des, char *entry, size_t size,
								uint64_t subkey[16])
{
	size_t		padd;
	uint8_t		*padded_input;
	size_t		i;
	uint64_t	data;
	uint64_t	vector;

	des->result_len = (size == 0) ? ft_strlen(entry) : size;
	padd = 8 - (des->result_len % 8);
	padded_input = (uint8_t*)ft_memalloc(des->result_len + padd);
	des->result = (uint8_t*)ft_memalloc(des->result_len + padd);
	ft_memcpy(padded_input, entry, des->result_len);
	ft_memset(padded_input + des->result_len, 0, padd);
	i = 0;
	hexastring_to_uint64(des->i_vector, &vector);
	uint64_t out;
	data = vector;
/*	while (i < des->result_len)
	{
		des_core(data, subkey, (uint8_t*)&out, CIPHER_ENCODE);
		data = (*(uint64_t*)(void*)&padded_input[i]) ^ out;
		ft_memcpy(&des->result[i], &data, 8);
		i += 8;
	}*/
	while (i < des->result_len)
	{
		des_core(data, subkey, (uint8_t*)&out, CIPHER_ENCODE);
		ft_print_memory(&out, sizeof(out));
		uint8_t keep = (out & 0xFF) ;
		ft_print_memory(&keep, sizeof(keep));
		keep = keep ^ padded_input[i];
		data = ((uint64_t)keep) << 56;
		ft_print_memory(&data, sizeof(data));
		ft_memcpy(&des->result[i], &keep, 1);
		i++;
	}
	ft_memdel((void**)&padded_input);
	if (des->passwd != NULL)
		salt_handler(des, NULL, 0);
}
