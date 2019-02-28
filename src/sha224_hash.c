/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha224_hash.c                                      :+:      :+:    :+:   */
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

static const uint32_t g_primary_int[64] =
{
    0x428a2f98,	0x71374491,	0xb5c0fbcf,	0xe9b5dba5,
    0x3956c25b,	0x59f111f1,	0x923f82a4,	0xab1c5ed5,
    0xd807aa98,	0x12835b01,	0x243185be,	0x550c7dc3,
    0x72be5d74,	0x80deb1fe,	0x9bdc06a7,	0xc19bf174,
    0xe49b69c1,	0xefbe4786,	0x0fc19dc6,	0x240ca1cc,
    0x2de92c6f,	0x4a7484aa,	0x5cb0a9dc,	0x76f988da,
    0x983e5152,	0xa831c66d,	0xb00327c8,	0xbf597fc7,
    0xc6e00bf3,	0xd5a79147,	0x06ca6351,	0x14292967,
    0x27b70a85,	0x2e1b2138,	0x4d2c6dfc,	0x53380d13,
    0x650a7354,	0x766a0abb,	0x81c2c92e,	0x92722c85,
    0xa2bfe8a1,	0xa81a664b,	0xc24b8b70,	0xc76c51a3,
    0xd192e819,	0xd6990624,	0xf40e3585,	0x106aa070,
    0x19a4c116,	0x1e376c08,	0x2748774c,	0x34b0bcb5,
    0x391c0cb3,	0x4ed8aa4a,	0x5b9cca4f,	0x682e6ff3,
    0x748f82ee,	0x78a5636f,	0x84c87814,	0x8cc70208,
    0x90befffa,	0xa4506ceb,	0xbef9a3f7,	0xc67178f2
};

static void		sha224_verbose(t_sha224 sha224)
{
	if (sha224.flags & SHA224_OARG_V_PAD || sha224.flags & SHA224_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha224.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha224.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha224.padding_size + 64);
	}
	if (sha224.flags & SHA224_OARG_V_BLOCK || sha224.flags & SHA224_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha224.block);
	}
}

static t_bool	sha224_padding(unsigned char *entry, t_sha224 *sha224, size_t entry_size)
{
	sha224->entry_size_b = entry_size * 8;
	sha224->padding_size = sha224->entry_size_b + 1;
	while ((sha224->padding_size % 512) != 448)
		sha224->padding_size++;
	sha224->zero_padding = sha224->padding_size - sha224->entry_size_b - 1;
	sha224->block = (sha224->padding_size + 64) / 512;
	sha224_verbose(*sha224);
	if (!(sha224->input = (char*)ft_memalloc((sha224->padding_size + 64) >> 3)))
		return (false);
	ft_memset(sha224->input, 0, (sha224->padding_size + 64) >> 3);
	ft_memcpy(sha224->input, entry, entry_size);
	sha224->input[entry_size] = (char)128;
	encode64_bendian(sha224->entry_size_b, &sha224->input[(sha224->padding_size >> 3)]);
	if (sha224->flags & SHA224_OARG_D_PAD || sha224->flags & SHA224_OARG_D_ALL)
		ft_print_memory(sha224->input, (sha224->padding_size + 64) >> 3);
	// init hash values
	sha224->hash[SHA224_A] = HASH_CONST_SHA224_A;
	sha224->hash[SHA224_B] = HASH_CONST_SHA224_B;
	sha224->hash[SHA224_C] = HASH_CONST_SHA224_C;
	sha224->hash[SHA224_D] = HASH_CONST_SHA224_D;
	sha224->hash[SHA224_E] = HASH_CONST_SHA224_E;
	sha224->hash[SHA224_F] = HASH_CONST_SHA224_F;
	sha224->hash[SHA224_G] = HASH_CONST_SHA224_G;
	sha224->hash[SHA224_H] = HASH_CONST_SHA224_H;
	return (true);
}

static void		sha224_init_loop(t_sha224 *sha224,
							size_t bloc, uint32_t (*word)[16])
{
	int i;

	i = -1;
	if (sha224->flags & SHA224_OARG_D_BLOCK || sha224->flags & SHA224_OARG_D_ALL)
	{
		ft_putstrcol(SH_RED, "Block:");
		ft_putnbrendl((int)bloc);
	}
	while (++i < 16)
	{
		ft_memcpy(&(*word)[i], &sha224->input[(bloc * 64) + ((size_t)i * 4)],
					sizeof(uint32_t));
		// in big endian
		(*word)[i] = swap_uint32((*word)[i]);
		if (sha224->flags & SHA224_OARG_D_BLOCK || sha224->flags & SHA224_OARG_D_ALL)
		{
			ft_putstrcol(SH_YELLOW, "[");
			ft_putnbr(i);
			ft_putstrcol(SH_YELLOW, "]:\t");
			ft_print_memory(&(*word)[i], sizeof(uint32_t));
		}
	}
}


static void		sha224_main_loop(t_sha224 *sha224,
								 uint32_t (*hash_register)[SHA224_N_REGISTER], uint32_t (*word)[16])
{
	int t;

	// 1:
	t = -1;
	while (++t < 16)
		sha224->Wt[t] = (*word)[t];
	t--;
	while (++t < 64)
		sha224->Wt[t] = sha224_func_sig1(sha224->Wt[t - 2]) + sha224->Wt[t -7]
		+ sha224_func_sig0(sha224->Wt[t - 15]) + sha224->Wt[t - 16];

	// 2: On initialise hash register avec les valeurs de hachage du tour précédent
	ft_memcpy(hash_register, &sha224->hash, sizeof(uint32_t) * SHA224_N_REGISTER);

	// 3:
	t = -1;
	while (++t < 64)
	{
		sha224->tmp1 = (*hash_register)[SHA224_H] + sha224_func_sum1((*hash_register)[SHA224_E])
		+ sha224_func_ch((*hash_register)[SHA224_E], (*hash_register)[SHA224_F], (*hash_register)[SHA224_G])
		+ g_primary_int[t] + sha224->Wt[t];
		sha224->tmp2 = sha224_func_sum0((*hash_register)[SHA224_A])
		+ sha224_func_maj((*hash_register)[SHA224_A], (*hash_register)[SHA224_B], (*hash_register)[SHA224_C]);
		(*hash_register)[SHA224_H] = (*hash_register)[SHA224_G];
		(*hash_register)[SHA224_G] = (*hash_register)[SHA224_F];
		(*hash_register)[SHA224_F] = (*hash_register)[SHA224_E];
		(*hash_register)[SHA224_E] = (*hash_register)[SHA224_D] + sha224->tmp1;
		(*hash_register)[SHA224_D] = (*hash_register)[SHA224_C];
		(*hash_register)[SHA224_C] = (*hash_register)[SHA224_B];
		(*hash_register)[SHA224_B] = (*hash_register)[SHA224_A];
		(*hash_register)[SHA224_A] = sha224->tmp1 + sha224->tmp2;
	}

	// 4:
	sha224->hash[SHA224_A] += (*hash_register)[SHA224_A];
	sha224->hash[SHA224_B] += (*hash_register)[SHA224_B];
	sha224->hash[SHA224_C] += (*hash_register)[SHA224_C];
	sha224->hash[SHA224_D] += (*hash_register)[SHA224_D];
	sha224->hash[SHA224_E] += (*hash_register)[SHA224_E];
	sha224->hash[SHA224_F] += (*hash_register)[SHA224_F];
	sha224->hash[SHA224_G] += (*hash_register)[SHA224_G];
	sha224->hash[SHA224_H] += (*hash_register)[SHA224_H];
}

static char		*sha224_concat_hash(t_sha224 sha224)
{
	char	footprint[224 + 1];
	char	*hash_str;
	int		i;

	i = -1;
	hash_str = NULL;
	ft_memset(&footprint, 0, 224 + 1);
	while (++i < SHA224_N_REGISTER - 1)
	{
		hash_str = itoa_base_uint32(sha224.hash[i], 16);
		ft_strncpy(&footprint[i * 8], hash_str, 8);
		ft_strdel(&hash_str);
	}
	return (ft_strdup(footprint));
}

char			*sha224_digest(unsigned char *entry, size_t entry_size,
							uint32_t flags)
{
	t_sha224	sha224;
	uint32_t	word[16];
	uint32_t	hash_register[SHA224_N_REGISTER];
	size_t		block;

	block = 0;
	ft_memset(&sha224, 0, sizeof(sha224));
	sha224.flags = flags;
	if (!(sha224_padding(entry, &sha224, entry_size)))
		return (NULL);
	while (block < sha224.block)
	{
		sha224_init_loop(&sha224, block, &word);
		sha224_main_loop(&sha224, &hash_register, &word);
		block++;
	}
	return (sha224_concat_hash(sha224));
}
