/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_ofb_cfb_treatment.c                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:56:07 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:56:17 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

void	des_ofb_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	des_ofb_cipher(des, entry, size, subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = des->out;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, (char*)des->result, des->result_len);
	}
	else
		write(des->out, des->result, des->result_len);
}

void	des_ofb_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = B64_USE_RESULT_AS_OUT;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, entry, size);
		des_ofb_cipher(des, b64.result, b64.result_len, subkey);
		ft_strdel(&b64.result);
	}
	else
		des_ofb_cipher(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}

void	des_cfb_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	des_cfb_cipher(des, entry, size, subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = des->out;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, (char*)des->result, des->result_len);
	}
	else
		write(des->out, des->result, des->result_len);
}

void	des_cfb_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = B64_USE_RESULT_AS_OUT;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, entry, size);
		des_cfb_cipher(des, b64.result, b64.result_len, subkey);
		ft_strdel(&b64.result);
	}
	else
		des_cfb_cipher(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}
