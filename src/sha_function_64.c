/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_function_64.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 12:55:05 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 20:30:03 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

/*
** Lookup table,
*/

static const uint64_t g_sha_64_k[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
	0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
	0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
	0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
	0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
	0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
	0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
	0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
	0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

uint64_t	sha_64_func_tri(t_sha_func func, uint64_t x, uint64_t y, uint64_t z)
{
	if (func == CH)
		return ((x & y) ^ (~x & z));
	if (func == MAJ)
		return ((x & y) ^ (x & z) ^ (y & z));
	return (0);
}

uint64_t	sha_64_func_mono(t_sha_func func, uint64_t x)
{
	if (func == SUM0)
		return (rotate_r_64(x, 28) ^ rotate_r_64(x, 34) ^ rotate_r_64(x, 39));
	if (func == SUM1)
		return (rotate_r_64(x, 14) ^ rotate_r_64(x, 18) ^ rotate_r_64(x, 41));
	if (func == SIG0)
		return (rotate_r_64(x, 1) ^ rotate_r_64(x, 8) ^ (x >> 7));
	if (func == SIG1)
		return (rotate_r_64(x, 19) ^ rotate_r_64(x, 61) ^ (x >> 6));
	return (0);
}

void		sha_64_core(t_sha_64 *sha,
						uint64_t (*hash)[SHA_N_REGISTER])
{
	int t;

	t = -1;
	while (++t < 80)
	{
		sha->tmp1 = (*hash)[SHA_H] + sha_64_func_mono(SUM1, (*hash)[SHA_E])
		+ sha_64_func_tri(CH, (*hash)[SHA_E], (*hash)[SHA_F], (*hash)[SHA_G])
		+ g_sha_64_k[t] + sha->wt[t];
		sha->tmp2 = sha_64_func_mono(SUM0, (*hash)[SHA_A])
		+ sha_64_func_tri(MAJ, (*hash)[SHA_A], (*hash)[SHA_B], (*hash)[SHA_C]);
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
