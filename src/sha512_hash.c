/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha512_hash.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/26 18:59:43 by banthony          #+#    #+#             */
/*   Updated: 2019/02/27 20:15:53 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

/*
** Lookup table,
*/

static const uint64_t g_primary_int[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void		sha512_verbose(t_sha512 sha512)
{
	if (sha512.flags & SHA512_OARG_V_PAD || sha512.flags & SHA512_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha512.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha512.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha512.padding_size + 64);
	}
	if (sha512.flags & SHA512_OARG_V_BLOCK || sha512.flags & SHA512_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha512.block);
	}
}

static t_bool	sha512_padding(unsigned char *entry, t_sha512 *sha512, size_t entry_size)
{
	sha512->entry_size_b = entry_size * 8;
	sha512->padding_size = sha512->entry_size_b + 1;
	while ((sha512->padding_size % 1024) != 960)
		sha512->padding_size++;
	sha512->zero_padding = sha512->padding_size - sha512->entry_size_b - 1;
	sha512->block = (sha512->padding_size + 64) / 1024;
	sha512_verbose(*sha512);
	if (!(sha512->input = (char*)ft_memalloc((sha512->padding_size + 64) >> 3)))
		return (false);
	ft_memset(sha512->input, 0, (sha512->padding_size + 64) >> 3);
	ft_memcpy(sha512->input, entry, entry_size);
	sha512->input[entry_size] = (char)128;
	encode64_bendian(sha512->entry_size_b, &sha512->input[(sha512->padding_size >> 3)]);
	if (sha512->flags & SHA512_OARG_D_PAD || sha512->flags & SHA512_OARG_D_ALL)
		ft_print_memory(sha512->input, (sha512->padding_size + 64) >> 3);
	// init hash values
	sha512->hash[SHA512_A] = HASH_CONST_SHA512_A;
	sha512->hash[SHA512_B] = HASH_CONST_SHA512_B;
	sha512->hash[SHA512_C] = HASH_CONST_SHA512_C;
	sha512->hash[SHA512_D] = HASH_CONST_SHA512_D;
	sha512->hash[SHA512_E] = HASH_CONST_SHA512_E;
	sha512->hash[SHA512_F] = HASH_CONST_SHA512_F;
	sha512->hash[SHA512_G] = HASH_CONST_SHA512_G;
	sha512->hash[SHA512_H] = HASH_CONST_SHA512_H;
	return (true);
}

static void		sha512_init_loop(t_sha512 *sha512,
							size_t bloc, uint64_t (*word)[16])
{
	int i;

	i = -1;
	if (sha512->flags & SHA512_OARG_D_BLOCK || sha512->flags & SHA512_OARG_D_ALL)
	{
		ft_putstrcol(SH_RED, "Block:");
		ft_putnbrendl((int)bloc);
	}
	while (++i < 16)
	{
		ft_memcpy(&(*word)[i], &sha512->input[(bloc * 64) + ((size_t)i * 8)],
					sizeof(uint64_t));
		// in big endian
		(*word)[i] = swap_uint64((*word)[i]);
		if (sha512->flags & SHA512_OARG_D_BLOCK || sha512->flags & SHA512_OARG_D_ALL)
		{
			ft_putstrcol(SH_YELLOW, "[");
			ft_putnbr(i);
			ft_putstrcol(SH_YELLOW, "]:\t");
			ft_print_memory(&(*word)[i], sizeof(uint64_t));
		}
	}
}


static void		sha512_main_loop(t_sha512 *sha512,
								 uint64_t (*hash_register)[SHA512_N_REGISTER], uint64_t (*word)[16])
{
	int t;

	// 1:
	t = -1;
	while (++t < 16)
		sha512->Wt[t] = (*word)[t];
	t--;
	while (++t < 80)
		sha512->Wt[t] = sha512_func_sig1(sha512->Wt[t - 2]) + sha512->Wt[t -7]
		+ sha512_func_sig0(sha512->Wt[t - 15]) + sha512->Wt[t - 16];

	// 2: On initialise hash register avec les valeurs de hachage du tour précédent
	ft_memcpy(hash_register, &sha512->hash, sizeof(uint64_t) * SHA512_N_REGISTER);

	// 3:
	t = -1;
	while (++t < 80)
	{
		sha512->tmp1 = (*hash_register)[SHA512_H] + sha512_func_sum1((*hash_register)[SHA512_E])
		+ sha512_func_ch((*hash_register)[SHA512_E], (*hash_register)[SHA512_F], (*hash_register)[SHA512_G])
		+ g_primary_int[t] + sha512->Wt[t];
		sha512->tmp2 = sha512_func_sum0((*hash_register)[SHA512_A])
		+ sha512_func_maj((*hash_register)[SHA512_A], (*hash_register)[SHA512_B], (*hash_register)[SHA512_C]);
		(*hash_register)[SHA512_H] = (*hash_register)[SHA512_G];
		(*hash_register)[SHA512_G] = (*hash_register)[SHA512_F];
		(*hash_register)[SHA512_F] = (*hash_register)[SHA512_E];
		(*hash_register)[SHA512_E] = (*hash_register)[SHA512_D] + sha512->tmp1;
		(*hash_register)[SHA512_D] = (*hash_register)[SHA512_C];
		(*hash_register)[SHA512_C] = (*hash_register)[SHA512_B];
		(*hash_register)[SHA512_B] = (*hash_register)[SHA512_A];
		(*hash_register)[SHA512_A] = sha512->tmp1 + sha512->tmp2;
	}

	// 4:
	sha512->hash[SHA512_A] += (*hash_register)[SHA512_A];
	sha512->hash[SHA512_B] += (*hash_register)[SHA512_B];
	sha512->hash[SHA512_C] += (*hash_register)[SHA512_C];
	sha512->hash[SHA512_D] += (*hash_register)[SHA512_D];
	sha512->hash[SHA512_E] += (*hash_register)[SHA512_E];
	sha512->hash[SHA512_F] += (*hash_register)[SHA512_F];
	sha512->hash[SHA512_G] += (*hash_register)[SHA512_G];
	sha512->hash[SHA512_H] += (*hash_register)[SHA512_H];
}

static char		*sha512_concat_hash(t_sha512 sha512)
{
	char	footprint[512 + 1];
	char	*hash_str;
	int		i;

	i = -1;
	hash_str = NULL;
	ft_memset(&footprint, 0, 512 + 1);
	while (++i < SHA512_N_REGISTER)
	{
		hash_str = itoa_base_uint64(sha512.hash[i], 16);
		printf("%s\n", hash_str);
		printf("%08llx\n", sha512.hash[i]);
		ft_strncpy(&footprint[i * 16], hash_str, 16);
		ft_strdel(&hash_str);
	}
	return (ft_strdup(footprint));
}

char			*sha512_digest(unsigned char *entry, size_t entry_size,
							uint32_t flags)
{
	t_sha512	sha512;
	uint64_t	word[16];
	uint64_t	hash_register[SHA512_N_REGISTER];
	size_t		block;

	block = 0;
	ft_memset(&sha512, 0, sizeof(sha512));
	sha512.flags = flags;
	if (!(sha512_padding(entry, &sha512, entry_size)))
		return (NULL);
	while (block < sha512.block)
	{
		sha512_init_loop(&sha512, block, &word);
		sha512_main_loop(&sha512, &hash_register, &word);
		block++;
	}
	return (sha512_concat_hash(sha512));
}
