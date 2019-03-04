/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256_hash.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/26 18:59:43 by banthony          #+#    #+#             */
/*   Updated: 2019/03/04 20:25:56 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

/*
** Lookup table, ajout table pour sha512
*/

static const uint32_t g_primary_int[64] =
{
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

static void		sha256_verbose(t_sha256 sha256)
{
	if (sha256.flags & SHA256_OARG_V_PAD || sha256.flags & SHA256_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha256.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha256.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha256.padding_size + 64);
	}
	if (sha256.flags & SHA256_OARG_V_BLOCK || sha256.flags & SHA256_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha256.block);
	}
}

static t_bool	sha256_padding(unsigned char *entry, t_sha256 *sha256,
								size_t entry_size)
{
	sha256->entry_size_b = entry_size * 8;
	sha256->padding_size = sha256->entry_size_b + 1;
	while ((sha256->padding_size % 512) != 448)
		sha256->padding_size++;
	sha256->zero_padding = sha256->padding_size - sha256->entry_size_b - 1;
	sha256->block = (sha256->padding_size + 64) / 512;
	sha256_verbose(*sha256);
	if (!(sha256->input = (char*)ft_memalloc((sha256->padding_size + 64) >> 3)))
		return (false);
	ft_memset(sha256->input, 0, (sha256->padding_size + 64) >> 3);
	ft_memcpy(sha256->input, entry, entry_size);
	sha256->input[entry_size] = (char)128;
	encode64_bendian(sha256->entry_size_b, &sha256->input[(sha256->padding_size >> 3)]);
	if (sha256->flags & SHA256_OARG_D_PAD || sha256->flags & SHA256_OARG_D_ALL)
		ft_print_memory(sha256->input, (sha256->padding_size + 64) >> 3);
	// dispatcher here for each sha algo
	sha256->hash[SHA256_A] = HASH_CONST_SHA_A;
	sha256->hash[SHA256_B] = HASH_CONST_SHA_B;
	sha256->hash[SHA256_C] = HASH_CONST_SHA_C;
	sha256->hash[SHA256_D] = HASH_CONST_SHA_D;
	sha256->hash[SHA256_E] = HASH_CONST_SHA_E;
	sha256->hash[SHA256_F] = HASH_CONST_SHA_F;
	sha256->hash[SHA256_G] = HASH_CONST_SHA_G;
	sha256->hash[SHA256_H] = HASH_CONST_SHA_H;
	return (true);
}

static void		sha256_init_loop(t_sha256 *sha256,
							size_t bloc, uint32_t (*word)[16])
{
	int i;

	i = -1;
	if (sha256->flags & SHA256_OARG_D_BLOCK || sha256->flags & SHA256_OARG_D_ALL)
	{
		ft_putstrcol(SH_RED, "Block:");
		ft_putnbrendl((int)bloc);
	}
	while (++i < 16)
	{
		ft_memcpy(&(*word)[i], &sha256->input[(bloc * 64) + ((size_t)i * 4)],
					sizeof(uint32_t));
		// in big endian
		(*word)[i] = swap_uint32((*word)[i]);
		if (sha256->flags & SHA256_OARG_D_BLOCK || sha256->flags & SHA256_OARG_D_ALL)
		{
			ft_putstrcol(SH_YELLOW, "[");
			ft_putnbr(i);
			ft_putstrcol(SH_YELLOW, "]:\t");
			ft_print_memory(&(*word)[i], sizeof(uint32_t));
		}
	}
}


static void		sha256_main_loop(t_sha256 *sha256,
								 uint32_t (*hash_register)[SHA256_N_REGISTER], uint32_t (*word)[16])
{
	int t;

	// 1:
	t = -1;
	while (++t < 16)
		sha256->Wt[t] = (*word)[t];
	t--;
	while (++t < 64)
		sha256->Wt[t] = sha256_func_sig1(sha256->Wt[t - 2]) + sha256->Wt[t -7]
		+ sha256_func_sig0(sha256->Wt[t - 15]) + sha256->Wt[t - 16];

	// 2: On initialise hash register avec les valeurs de hachage du tour précédent
	ft_memcpy(hash_register, &sha256->hash, sizeof(uint32_t) * SHA256_N_REGISTER);

	// 3:
	t = -1;
	while (++t < 64)
	{
		sha256->tmp1 = (*hash_register)[SHA256_H] + sha256_func_sum1((*hash_register)[SHA256_E])
		+ sha256_func_ch((*hash_register)[SHA256_E], (*hash_register)[SHA256_F], (*hash_register)[SHA256_G])
		+ g_primary_int[t] + sha256->Wt[t];
		sha256->tmp2 = sha256_func_sum0((*hash_register)[SHA256_A])
		+ sha256_func_maj((*hash_register)[SHA256_A], (*hash_register)[SHA256_B], (*hash_register)[SHA256_C]);
		(*hash_register)[SHA256_H] = (*hash_register)[SHA256_G];
		(*hash_register)[SHA256_G] = (*hash_register)[SHA256_F];
		(*hash_register)[SHA256_F] = (*hash_register)[SHA256_E];
		(*hash_register)[SHA256_E] = (*hash_register)[SHA256_D] + sha256->tmp1;
		(*hash_register)[SHA256_D] = (*hash_register)[SHA256_C];
		(*hash_register)[SHA256_C] = (*hash_register)[SHA256_B];
		(*hash_register)[SHA256_B] = (*hash_register)[SHA256_A];
		(*hash_register)[SHA256_A] = sha256->tmp1 + sha256->tmp2;
	}

	// 4:
	sha256->hash[SHA256_A] += (*hash_register)[SHA256_A];
	sha256->hash[SHA256_B] += (*hash_register)[SHA256_B];
	sha256->hash[SHA256_C] += (*hash_register)[SHA256_C];
	sha256->hash[SHA256_D] += (*hash_register)[SHA256_D];
	sha256->hash[SHA256_E] += (*hash_register)[SHA256_E];
	sha256->hash[SHA256_F] += (*hash_register)[SHA256_F];
	sha256->hash[SHA256_G] += (*hash_register)[SHA256_G];
	sha256->hash[SHA256_H] += (*hash_register)[SHA256_H];
}

static char		*sha256_concat_hash(t_sha256 sha256)
{
	char	footprint[256 + 1];
	char	*hash_str;
	int		i;

	i = -1;
	hash_str = NULL;
	ft_memset(&footprint, 0, 256 + 1);
	// dispatcher sha concat
	while (++i < SHA256_N_REGISTER)
	{
		hash_str = itoa_base_uint32(sha256.hash[i], 16);
		ft_strncpy(&footprint[i * 8], hash_str, 8);
		ft_strdel(&hash_str);
	}
	return (ft_strdup(footprint));
}

char			*sha256_digest(unsigned char *entry, size_t entry_size,
							uint32_t flags)
{
	t_sha256	sha256;
	uint32_t	word[16];
	uint32_t	hash_register[SHA256_N_REGISTER];
	size_t		block;

	block = 0;
	ft_memset(&sha256, 0, sizeof(sha256));
	sha256.flags = flags;
	if (!(sha256_padding(entry, &sha256, entry_size)))
		return (NULL);
	while (block < sha256.block)
	{
		sha256_init_loop(&sha256, block, &word);
		sha256_main_loop(&sha256, &hash_register, &word);
		block++;
	}
	return (sha256_concat_hash(sha256));
}
