/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_hash_64.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 12:55:01 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 14:46:58 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

/*
** Lookup table,
*/

static const uint64_t g_sha_64_init[NB_CMD][8] = {
	[SHA512] = {
		HASH_CONST_SHA512_A,
		HASH_CONST_SHA512_B,
		HASH_CONST_SHA512_C,
		HASH_CONST_SHA512_D,
		HASH_CONST_SHA512_E,
		HASH_CONST_SHA512_F,
		HASH_CONST_SHA512_G,
		HASH_CONST_SHA512_H,
	},
	[SHA384] = {
		HASH_CONST_SHA384_A,
		HASH_CONST_SHA384_B,
		HASH_CONST_SHA384_C,
		HASH_CONST_SHA384_D,
		HASH_CONST_SHA384_E,
		HASH_CONST_SHA384_F,
		HASH_CONST_SHA384_G,
		HASH_CONST_SHA384_H,
	},
};

static t_bool	sha_padding(unsigned char *entry, t_sha_64 *sha,
								size_t entry_size)
{
	sha->entry_size_b = entry_size * 8;
	sha->padding_size = sha->entry_size_b + 1;
	while ((sha->padding_size % 1024) != 960)
		sha->padding_size++;
	sha->zero_padding = sha->padding_size - sha->entry_size_b - 1;
	sha->block = (sha->padding_size + 64) / 1024;
	sha64_verbose(*sha);
	if (!(sha->input = (char*)ft_memalloc((sha->padding_size + 64) >> 3)))
		return (false);
	ft_memset(sha->input, 0, (sha->padding_size + 64) >> 3);
	ft_memcpy(sha->input, entry, entry_size);
	sha->input[entry_size] = (char)128;
	encode64_bendian(sha->entry_size_b, &sha->input[(sha->padding_size >> 3)]);
	if (sha->flags & SHA_OARG_D_PAD || sha->flags & SHA_OARG_D_ALL)
		ft_print_memory(sha->input, (sha->padding_size + 64) >> 3);
	return (true);
}

static void		sha_64_init_loop(t_sha_64 *sha,
							size_t bloc, uint64_t (*word)[16])
{
	int i;

	i = -1;
	if (sha->flags & SHA_OARG_D_BLOCK || sha->flags & SHA_OARG_D_ALL)
	{
		ft_putstrcol(SH_RED, "Block:");
		ft_putnbrendl((int)bloc);
	}
	while (++i < 16)
	{
		ft_memcpy(&(*word)[i], &sha->input[(bloc * 128) + ((size_t)i * 8)],
					sizeof(uint64_t));
		(*word)[i] = swap_uint64((*word)[i]);
		if (sha->flags & SHA_OARG_D_BLOCK || sha->flags & SHA_OARG_D_ALL)
		{
			ft_putstrcol(SH_YELLOW, "[");
			ft_putnbr(i);
			ft_putstrcol(SH_YELLOW, "]:\t");
			ft_print_memory(&(*word)[i], sizeof(uint64_t));
		}
	}
}

static void		sha_64_main_loop(t_sha_64 *sha,
									uint64_t (*hash)[SHA_N_REGISTER],
									uint64_t (*word)[16])
{
	int t;

	t = -1;
	while (++t < 16)
		sha->Wt[t] = (*word)[t];
	t--;
	while (++t < 80)
	{
		sha->Wt[t] = sha_64_func_mono(SIG1, sha->Wt[t - 2]) + sha->Wt[t - 7]
		+ sha_64_func_mono(SIG0, sha->Wt[t - 15]) + sha->Wt[t - 16];
	}
	ft_memcpy(hash, &sha->hash, sizeof(uint64_t) * SHA_N_REGISTER);
	sha_64_core(sha, hash);
	sha->hash[SHA_A] += (*hash)[SHA_A];
	sha->hash[SHA_B] += (*hash)[SHA_B];
	sha->hash[SHA_C] += (*hash)[SHA_C];
	sha->hash[SHA_D] += (*hash)[SHA_D];
	sha->hash[SHA_E] += (*hash)[SHA_E];
	sha->hash[SHA_F] += (*hash)[SHA_F];
	sha->hash[SHA_G] += (*hash)[SHA_G];
	sha->hash[SHA_H] += (*hash)[SHA_H];
}

static char		*sha_64_concat_hash(t_sha_64 sha, t_cmd_type cmd)
{
	char	footprint[512 + 1];
	char	*hash_str;
	int		i;
	int		nb_register;

	i = -1;
	hash_str = NULL;
	ft_memset(&footprint, 0, 512 + 1);
	nb_register = SHA_N_REGISTER;
	if (cmd == SHA384)
		nb_register -= 2;
	while (++i < nb_register)
	{
		hash_str = itoa_base_uint64(sha.hash[i], 16);
		ft_strncpy(&footprint[i * 16], hash_str, 16);
		ft_strdel(&hash_str);
	}
	return (ft_strdup(footprint));
}

char			*sha_64_digest(t_cmd_type cmd, unsigned char *entry,
								size_t entry_size,
								uint32_t flags)
{
	t_sha_64	sha;
	uint64_t	word[16];
	uint64_t	hash_register[SHA_N_REGISTER];
	size_t		block;

	block = 0;
	ft_memset(&sha, 0, sizeof(sha));
	sha.flags = flags;
	if (!(sha_padding(entry, &sha, entry_size)))
		return (NULL);
	sha.hash[SHA_A] = g_sha_64_init[cmd][0];
	sha.hash[SHA_B] = g_sha_64_init[cmd][1];
	sha.hash[SHA_C] = g_sha_64_init[cmd][2];
	sha.hash[SHA_D] = g_sha_64_init[cmd][3];
	sha.hash[SHA_E] = g_sha_64_init[cmd][4];
	sha.hash[SHA_F] = g_sha_64_init[cmd][5];
	sha.hash[SHA_G] = g_sha_64_init[cmd][6];
	sha.hash[SHA_H] = g_sha_64_init[cmd][7];
	while (block < sha.block)
	{
		sha_64_init_loop(&sha, block, &word);
		sha_64_main_loop(&sha, &hash_register, &word);
		block++;
	}
	return (sha_64_concat_hash(sha, cmd));
}
