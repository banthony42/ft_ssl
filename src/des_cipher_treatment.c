/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher_treatment.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/24 15:57:57 by banthony          #+#    #+#             */
/*   Updated: 2019/10/30 10:44:12 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

void	des_ecb_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
										size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	des_ecb_encode(des, entry, size, subkey);
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

void	des_ecb_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
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
		des_ecb_decode(des, b64.result, b64.result_len, subkey);
		ft_strdel(&b64.result);
	}
	else
		des_ecb_decode(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}

void	des_cbc_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	generate_keys(key, &subkey);
	des_cbc_encode(des, entry, size, subkey);
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

void	des_cbc_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
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
		des_cbc_decode(des, b64.result, b64.result_len, subkey);
		ft_strdel(&b64.result);
	}
	else
		des_cbc_decode(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}
