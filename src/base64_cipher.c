/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_cipher.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/26 14:21:32 by abara             #+#    #+#             */
/*   Updated: 2019/10/29 14:22:46 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

static const char g_base64_table[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char g_base64_url_table[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
**	If padding == 4:
**	At the end of the loop there is still 8bits unused, so
**	we have added 4 bits set to zero, then we can read the 12 last bits.
**
**	If paddding == 2:
**	At the end of the loop there is still 16bits unused, so
**	we have added 2 bits set to zero, then we can read the 18 last bits.
*/

static void		encode_b64_end(char pad, uint8_t *out, t_base64 *b64)
{
	if (pad == 4)
	{
		ft_putchar_fd(b64->table[out[0] >> 2], b64->out);
		ft_putchar_fd(b64->table[((out[0] & 0x03) << 4)
							| out[1] >> 4], b64->out);
		ft_putstr_fd("==", b64->out);
	}
	else if (pad == 2)
	{
		ft_putchar_fd(b64->table[out[0] >> 2], b64->out);
		ft_putchar_fd(b64->table[((out[0] & 0x03) << 4)
							| out[1] >> 4], b64->out);
		ft_putchar_fd(b64->table[((out[1] & 0xf) << 2)
							| out[2] >> 6], b64->out);
		ft_putchar_fd('=', b64->out);
	}
}

/*
**	Parse entry by block of 3 char because : (3 * 8 bits = 24 bits)
**	Read all the 24 bits by step of 6 bits.
**	Use the value of this 6 bits for each step, as index
**	in the base64_table / base64_url_table.
**	This give us the cipher for the current block of 3 char.
**	At the end read the last 12 bits or 18bits and put some '='.
**
**	Example with the entry "cou"
**	Block of 3 octet, split into 4 field of 6 bits :
**
**	0b011000|11		'c'
**	0b0110|1111		'o'
**	0b01|110101		'u'
**
**	A block of 6 bits give us a number, use it in the base64 table:
**
**	00|011000	24	'Y'
**	00|110110	54	'2'
**	00|111101	61	'9'
**	00|110101	53	'1'
*/

static void		encode_b64(char *entry, char padding, t_base64 *b64, size_t len)
{
	uint8_t			*end;
	uint8_t			*out;
	uint8_t			buf[3];

	out = (uint8_t*)entry;
	end = (uint8_t*)(entry + len);
	while ((end - out) >= 3)
	{
		buf[0] = (uint8_t)out[0];
		buf[1] = (uint8_t)out[1];
		buf[2] = (uint8_t)out[2];
		ft_putchar_fd(b64->table[buf[0] >> 2], b64->out);
		ft_putchar_fd(b64->table[((buf[0] & 0x03) << 4)
						| buf[1] >> 4], b64->out);
		ft_putchar_fd(b64->table[((buf[1] & 0xf) << 2)
						| buf[2] >> 6], b64->out);
		ft_putchar_fd(b64->table[((buf[2] & 0x3f))], b64->out);
		out += 3;
	}
	ft_memset(buf, 0, 3);
	ft_memcpy(buf, out, (size_t)(end - out));
	encode_b64_end(padding, buf, b64);
	ft_putchar_fd('\n', b64->out);
}

/*
**	Parse entry by block of 4 char because we are in decode mode:
**	In base64, a ciphered char is coded on 6 bits.
**	If we parse the entry by block of 4 ciphered char we have: 4 * 6 = 24 bits.
**	Then we have to concat this bits and split it into 3 bytes: 3 * 8 = 24 bits.
**	Finally we have our 3 deciphered char.
**
**	The deciphering works with a decode table.
**	This decode table was built with the encode table using this tricks:
**	decode_table[encode_table[i]] = i;
**
**	Example with i = 0 : where  encode_table[0] = 'A'
**	decode_table[ 'A' ] = 0;
**
**	The tricks is to use ascii value of 'A' as index to store the value of 'A'.
*/

static void		decode_b64_core(t_base64 *b64, t_decode_block block)
{
	uint8_t			out[3];

	ft_memset(out, 0, 3);
	out[0] = (uint8_t)((block.i_0 << 2) | block.i_1 >> 4);
	out[1] = (uint8_t)((block.i_1 << 4) | block.i_2 >> 2);
	out[2] = (uint8_t)((block.i_2 << 6) | block.i_3);
	if (out[0] && b64->out < 0)
		ft_strncat(b64->result, (char*)&out[0], 1);
	else if (out[0])
		ft_putchar_fd((char)out[0], b64->out);
	if (out[1] && b64->out < 0)
		ft_strncat(b64->result, (char*)&out[1], 1);
	else if (out[1])
		ft_putchar_fd((char)out[1], b64->out);
	if (out[2] && b64->out < 0)
		ft_strncat(b64->result, (char*)&out[2], 1);
	else if (out[2])
		ft_putchar_fd((char)out[2], b64->out);
}

static void		decode_b64(char *entry, t_base64 *b64,
								int b64_decode[255], size_t len)
{
	int				i;
	t_decode_block	block;

	if (!is_valid_ciphering(entry, (int)len, &b64->result_len, b64->b64_url))
		return ;
	if (b64->out < 0)
		b64->result = ft_strnew(len + 4);
	ft_memset(&block, 0, sizeof(block));
	i = 0;
	while (i < (int)len)
	{
		if (entry[i] != '\n')
			ft_strncat(block.char_array, &entry[i], 1);
		if (ft_strlen(block.char_array) >= 4)
		{
			block.i_0 = b64decode((int)block.char_array[0], b64_decode);
			block.i_1 = b64decode((int)block.char_array[1], b64_decode);
			block.i_2 = b64decode((int)block.char_array[2], b64_decode);
			block.i_3 = b64decode((int)block.char_array[3], b64_decode);
			decode_b64_core(b64, block);
			ft_memset(block.char_array, 0, 4);
		}
		i++;
	}
}

void			base64_cipher(t_base64 *b64, char *entry, size_t len)
{
	char			padding;
	int				b64_decode[255];
	int				j;

	if (!entry)
		return ;
	(b64->b64_url == true) ? ft_strncpy(b64->table, g_base64_url_table, 65)
		: ft_strncpy(b64->table, g_base64_table, 65);
	if (b64->cipher_mode == CIPHER_ENCODE)
	{
		if ((padding = (len * 8) % 24) == 8)
			padding = 4;
		else
			padding = (padding == 16) ? (2) : (0);
		encode_b64(entry, padding, b64, len);
	}
	else if (b64->cipher_mode == CIPHER_DECODE)
	{
		j = -1;
		ft_memset(b64_decode, 0, sizeof(b64_decode));
		while (++j < (int)sizeof(b64->table))
			b64_decode[(int)b64->table[j]] = j;
		decode_b64(entry, b64, b64_decode, len);
	}
}
