/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256_hash.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/26 18:59:43 by banthony          #+#    #+#             */
/*   Updated: 2019/02/26 20:05:15 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

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

static t_bool	sha256_padding(unsigned char *entry, t_sha256 *sha256, size_t entry_size)
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
	encode64_lendian(sha256->entry_size_b, &sha256->input[(sha256->padding_size >> 3)]);
	if (sha256->flags & SHA256_OARG_D_PAD || sha256->flags & SHA256_OARG_D_ALL)
		ft_print_memory(sha256->input, (sha256->padding_size + 64) >> 3);
	// init hash register here, use a loop
	// sha256->hash[SHA256_A] = valeur
	return (true);
}


static void		sha256_init_loop(t_sha256 *sha256, uint32_t (*hash_register)[N_INDEX],
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
		if (sha256->flags & SHA256_OARG_D_BLOCK || sha256->flags & SHA256_OARG_D_ALL)
		{
			ft_putstrcol(SH_YELLOW, "[");
			ft_putnbr(i);
			ft_putstrcol(SH_YELLOW, "]:\t");
			ft_print_memory(&(*word)[i], sizeof(uint32_t));
		}
	}
	// update hash_register here
}

/*
static void		sha256_main_loop(uint32_t (*word)[16],
								uint32_t (*hash_r)[MD5_N_REGISTER], int i)
{
	t_md5_data md5_data;

	md5_data.f = 0;
	md5_data.i_w = (uint32_t)i;
	if (0 <= i && i <= 15)
		md5_data.f = md5_func_f((*hash_r)[MD5_B], (*hash_r)[MD5_C], (*hash_r)[MD5_D]);
	else if (16 <= i && i <= 31)
	{
		md5_data.f = md5_func_g((*hash_r)[MD5_B], (*hash_r)[MD5_C], (*hash_r)[MD5_D]);
		md5_data.i_w = (5 * i + 1) % 16;
	}
	else if (32 <= i && i <= 47)
	{
		md5_data.f = md5_func_h((*hash_r)[MD5_B], (*hash_r)[MD5_C], (*hash_r)[MD5_D]);
		md5_data.i_w = (3 * i + 5) % 16;
	}
	else if (48 <= i && i <= 63)
	{
		md5_data.f = md5_func_i((*hash_r)[MD5_B], (*hash_r)[MD5_C], (*hash_r)[MD5_D]);
		md5_data.i_w = (7 * i) % 16;
	}
	md5_compute(word, hash_r, md5_data, i);
	}*/

static char		*sha256_concat_hash(t_sha256 sha256)
{
	(void)sha256;
	return (ft_strdup("CHAT256"));
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
		//	sha256_init_loop
		block++;
	}
	(void)hash_register;
	(void)word;
	return (sha256_concat_hash(sha256));
}
