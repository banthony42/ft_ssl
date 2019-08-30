/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_cipher.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/26 14:21:32 by abara             #+#    #+#             */
/*   Updated: 2019/07/26 14:53:09 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

static const char g_base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char g_base64_url_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	// If file input and entry are both present,
	// determine which data will be ciphered.

static void encode_b64(char *entry, size_t entry_len, unsigned char padding, t_base64 b64)
{
	char			*end;
	char			*output;
	unsigned char	newline_counter;
	char table[65] = {0};

	(b64.b64_url == true) ? ft_strncpy(table, g_base64_url_table, 65) : ft_strncpy(table, g_base64_table, 65);
	newline_counter = 0;
	output = entry;
	end = entry + entry_len;
	while ((end - output) >= 3)
	{
		if (newline_counter >= 63) {
			ft_putchar_fd('\n', b64.out_fd);
			newline_counter = 0;
		}
		ft_putchar_fd(table[output[0] >> 2], b64.out_fd);
		ft_putchar_fd(table[((output[0] & 0x03) << 4) | output[1] >> 4], b64.out_fd);
		ft_putchar_fd(table[((output[1] & 0xf ) << 2) | output[2] >> 6], b64.out_fd);
		ft_putchar_fd(table[((output[2] & 0x3f))], b64.out_fd);
		newline_counter += 4;
		output += 3;
	}
	// Read 12 bits and add "=="
	if (padding == 4)
	{
		ft_putchar_fd(table[output[0] >> 2], b64.out_fd);
		ft_putchar_fd(table[((output[0] & 0x03) << 4) | output[1] >> 4], b64.out_fd);
		ft_putstr_fd("==", b64.out_fd);
	}
	// Read 18 bits and add "="
	if (padding == 2)
	{
		ft_putchar_fd(table[output[0] >> 2], b64.out_fd);
		ft_putchar_fd(table[((output[0] & 0x03) << 4) | output[1] >> 4], b64.out_fd);
		ft_putchar_fd(table[((output[1] & 0xf ) << 2) | output[2] >> 6], b64.out_fd);
		ft_putchar_fd('=', b64.out_fd);
	}
	ft_putchar_fd('\n', b64.out_fd);
}

	//	Block of 3 octet, split into 4 field of 6 bits :
	//	0b011000|11		'c'
	//	0b0110|1111		'o'
	//	0b01|110101		'u'
	//
	//	Give us :
	//
	//	00|011000	24	'Y'
	//	00|110110	54	'2'
	//	00|111101	61	'9'
	//	00|110101	53	'1'

// 00|000010	'C'
// 00|100000	'g'
// 000000000	'='
// 000000000	'='

// 00001010 00000000 00000000 00000000

static void decode_b64(char *entry, size_t entry_len, t_base64 b64)
{
	// Have to parse base 64 string, foreach block of 4 char, encode 24 bits.
	// ft_putstr("==[");
	// ft_putstr(entry);
	// ft_putendl("]==");
	char table[65] = {0};

	(b64.b64_url == true) ? ft_strncpy(table, g_base64_url_table, 65) : ft_strncpy(table, g_base64_table, 65);

	// Build of the decode table, to transform char into index of g_base64_table
	int base64_decode_table[255];
	ft_memset(base64_decode_table,'#', sizeof(base64_decode_table));
	int j = -1;
	while (++j < (int)sizeof(table))
		base64_decode_table[(int)table[j]] = j;
	base64_decode_table['='] = 0;

	size_t i = 0;
	char block[5] = {0};
	while (i < entry_len)
	{
		ft_strncat(block, &entry[i], 1);
		if (ft_strlen(block) >= 4){
			int ib64_0 = base64_decode_table[(int)block[0]];
			int ib64_1 = base64_decode_table[(int)block[1]];
			int ib64_2 = base64_decode_table[(int)block[2]];
			int ib64_3 = base64_decode_table[(int)block[3]];

			ft_putchar_fd((char)((ib64_0 << 2) | (ib64_1 ) >> 4), b64.out_fd);
			ft_putchar_fd((char)((ib64_1 << 4) | (ib64_2 ) >> 2), b64.out_fd);
			ft_putchar_fd((char)((ib64_2 << 6) | (ib64_3 ) ), b64.out_fd);
			ft_memset(block, 0, 4);
		}
		i++;
	}
	// Last block with padding treatment
	// ft_putendl(block);
}

void	base64_cipher(t_base64 b64, char *entry)
{
	size_t			entry_len;
	unsigned char	padding;

	if (!entry)
		return ;
	entry_len = ft_strlen(entry);
	if (b64.cipher_mode == ENCODE)
	{
		if ((padding = (entry_len * 8) % 24) == 8)
			padding = 4;
		else if (padding == 16)
			padding = 2;
		else
			padding = 0;
		encode_b64(entry, entry_len, padding, b64);
	}
	else if (b64.cipher_mode == DECODE)
		decode_b64(entry, entry_len, b64);
}
