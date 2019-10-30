/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_core.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 15:05:17 by banthony          #+#    #+#             */
/*   Updated: 2019/10/30 13:35:01 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

/*
**	Initial permutation
*/
static const uint8_t	g_initp[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

/*
**	Expansion table
*/
static const uint8_t	g_expp[48] = {
	32, 1, 2, 3, 4, 5, 4, 5,
	6, 7, 8, 9, 8, 9, 10, 11,
	12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21,
	22, 23, 24, 25, 24, 25, 26, 27,
	28, 29, 28, 29, 30, 31, 32, 1
};

/*
**	End round permutation
*/
static const uint8_t	g_end_roundp[32] = {
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25
};

/*
**	Final permutation
*/
static const uint8_t	g_finalp[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

uint64_t	bits_permutation(uint64_t data, const uint8_t *matrix, size_t size)
{
	size_t		i;
	uint64_t	permuted_data;

	i = 0;
	permuted_data = 0;
	while (i < size)
	{
		if (((data << (matrix[i] - 1)) & FIRST_BIT_64) != 0)
			permuted_data += (FIRST_BIT_64 >> i);
		i++;
	}
	return (permuted_data);
}

static void	encryption_round(uint32_t *left, uint32_t *right,
								uint64_t subkey[16])
{
	int			i;
	uint64_t	xored_data;
	uint32_t	sbox_result;
	uint64_t	exp;

	i = -1;
	while (++i < 16)
	{
		exp = bits_permutation((uint64_t)(*right) << 32, g_expp, 48) >> 16;
		xored_data = exp ^ (subkey[i] >> 16);
		des_substitution(xored_data, &sbox_result);
		sbox_result = bits_permutation(((uint64_t)sbox_result << 32),
										g_end_roundp, 32) >> 32;
		sbox_result ^= *left;
		*left = *right;
		*right = sbox_result;
	}
}

static void	decryption_round(uint32_t *left, uint32_t *right,
								uint64_t subkey[16])
{
	int			i;
	uint64_t	exp;
	uint64_t	xored_data;
	uint32_t	tmp_left;
	uint32_t	sbox_result;

	i = 15;
	while (i >= 0)
	{
		tmp_left = *right;
		exp = bits_permutation((uint64_t)(*right) << 32, g_expp, 48) >> 16;
		xored_data = exp ^ (subkey[i] >> 16);
		des_substitution(xored_data, &sbox_result);
		sbox_result = bits_permutation(((uint64_t)sbox_result << 32),
										g_end_roundp, 32) >> 32;
		*right = *left ^ sbox_result;
		*left = tmp_left;
		i--;
	}
}

void		des_core(uint64_t data, uint64_t subkey[16], uint8_t *result,
						t_cipher_mode mode)
{
	uint32_t	right;
	uint32_t	left;

	data = bits_permutation(data, g_initp, 64);
	left = data >> 32;
	right = data & 0xFFFFFFFF;
	if (mode == CIPHER_ENCODE)
		encryption_round(&left, &right, subkey);
	else if (mode == CIPHER_DECODE)
		decryption_round(&left, &right, subkey);
	data = ((uint64_t)right << 32) | (left & 0xFFFFFFFFFFFFFFFF);
	data = bits_permutation(data, g_finalp, 64);
	data = swap_uint64(data);
	ft_memcpy(result, &data, 8);
}
