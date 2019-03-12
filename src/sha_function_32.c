/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_function_32.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 10:57:56 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 20:21:46 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

/*
** Lookup table,
*/

static const uint32_t	g_sha_32_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t	sha_32_func_tri(t_sha_func func, uint32_t x, uint32_t y, uint32_t z)
{
	if (func == CH)
		return ((x & y) ^ (~x & z));
	if (func == MAJ)
		return ((x & y) ^ (x & z) ^ (y & z));
	return (0);
}

uint32_t	sha_32_func_mono(t_sha_func func, uint32_t x)
{
	if (func == SUM0)
		return (rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22));
	if (func == SUM1)
		return (rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25));
	if (func == SIG0)
		return (rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3));
	if (func == SIG1)
		return (rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10));
	return (0);
}

void		sha_32_core(t_sha_32 *sha,
						uint32_t (*hash)[SHA_N_REGISTER])
{
	int t;

	t = -1;
	while (++t < 64)
	{
		sha->tmp1 = (*hash)[SHA_H] + sha_32_func_mono(SUM1, (*hash)[SHA_E])
		+ sha_32_func_tri(CH, (*hash)[SHA_E], (*hash)[SHA_F], (*hash)[SHA_G])
		+ g_sha_32_k[t] + sha->wt[t];
		sha->tmp2 = sha_32_func_mono(SUM0, (*hash)[SHA_A])
		+ sha_32_func_tri(MAJ, (*hash)[SHA_A], (*hash)[SHA_B], (*hash)[SHA_C]);
		(*hash)[SHA_H] = (*hash)[SHA_G];
		(*hash)[SHA_G] = (*hash)[SHA_F];
		(*hash)[SHA_F] = (*hash)[SHA_E];
		(*hash)[SHA_E] = (*hash)[SHA_D] + sha->tmp1;
		(*hash)[SHA_D] = (*hash)[SHA_C];
		(*hash)[SHA_C] = (*hash)[SHA_B];
		(*hash)[SHA_B] = (*hash)[SHA_A];
		(*hash)[SHA_A] = sha->tmp1 + sha->tmp2;
	}
}
