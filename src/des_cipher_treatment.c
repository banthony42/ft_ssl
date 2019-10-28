/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher_treatment.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/24 15:57:57 by banthony          #+#    #+#             */
/*   Updated: 2019/10/28 16:55:13 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

static const uint8_t	g_keyp[56] =
{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

void	des_ecb_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
										size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
		des_cbc_decode(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}

void	des_ofb_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	key;

	(void)cmd;
	hexastring_to_uint64(des->hexa_key, &key);
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
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

static void	generate_keys(uint64_t key, uint64_t (*subkey)[16])
{
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, subkey);
}

static void	des3_generate_keys(char *str_key, uint64_t (*subkey1)[16],
							uint64_t (*subkey2)[16], uint64_t (*subkey3)[16])
{
	uint64_t	key;
	char		*big_key;

	big_key = ft_strnew(255);
	ft_strncpy(big_key, str_key, ft_strlen(str_key));
	key = 0;
	hexastring_to_uint64(big_key, &key);
	generate_keys(key, subkey1);
	key = 0;
	hexastring_to_uint64(big_key + 16, &key);
	generate_keys(key, subkey2);
	key = 0;
	hexastring_to_uint64(big_key + 32, &key);
	generate_keys(key, subkey3);
	ft_strdel(&big_key);
}

void	des3_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	subkey2[16];
	uint64_t	subkey3[16];

	(void)cmd;
	des3_generate_keys(des->hexa_key, &subkey, &subkey2, &subkey3);
	des3_encode(des, entry, size, subkey, subkey2, subkey3);
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

void	des3_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64	b64;
	uint64_t	subkey[16];
	uint64_t	subkey2[16];
	uint64_t	subkey3[16];

	(void)cmd;
	des3_generate_keys(des->hexa_key, &subkey, &subkey2, &subkey3);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = B64_USE_RESULT_AS_OUT;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, entry, size);
		des3_decode(des, b64.result, b64.result_len, subkey, subkey2, subkey3);
		ft_strdel(&b64.result);
	}
	else
		des3_decode(des, entry, size, subkey, subkey2, subkey3);
	write(des->out, des->result, des->result_len);
}
