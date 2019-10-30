/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_subkey_gen.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:46:29 by banthony          #+#    #+#             */
/*   Updated: 2019/10/30 11:47:15 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

static const uint8_t g_shift_table[16] =
{
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

static const uint8_t g_key_comp[48] =
{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

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

void		generate_keys(uint64_t key, uint64_t (*subkey)[16])
{
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, subkey);
}

void		des3_generate_keys(char *str_key, t_des3_subkey *subkey)
{
	uint64_t	key;
	char		*big_key;

	key = 0;
	big_key = ft_strnew(192);
	ft_strncpy(big_key, str_key, ft_strlen(str_key));
	hexastring_to_uint64(big_key, &key);
	generate_keys(key, &subkey->s1);
	key = 0;
	hexastring_to_uint64(big_key + 16, &key);
	generate_keys(key, &subkey->s2);
	key = 0;
	hexastring_to_uint64(big_key + 32, &key);
	generate_keys(key, &subkey->s3);
	ft_strdel(&big_key);
}

static void	rotate_left_28(uint32_t *ptr, int shift)
{
	int i;

	i = -1;
	while (++i < shift)
	{
		*ptr <<= 1;
		if (((*ptr << 3) & FIRST_BIT_32) != 0)
			*ptr += (FIRST_BIT_32 >> 31);
	}
}

void		des_subkey_generation(uint64_t key, uint64_t (*subkey)[16])
{
	int			i;
	uint32_t	l_block;
	uint32_t	r_block;
	uint64_t	block_cat;
	uint64_t	keys;

	keys = key >> 8;
	r_block = (((1u << 28) - 1)) & keys;
	l_block = ((((1u << 28) - 1)) & (keys >> 28));
	i = -1;
	while (++i < 16)
	{
		rotate_left_28(&l_block, g_shift_table[i]);
		rotate_left_28(&r_block, g_shift_table[i]);
		block_cat = ((((1u << 28) - 1)) & r_block);
		block_cat |= ((((1u << 28) - 1)) & (uint64_t)l_block) << 28;
		block_cat = block_cat << 8;
		block_cat = bits_permutation(block_cat, g_key_comp, 48);
		(*subkey)[i] = block_cat;
	}
}
