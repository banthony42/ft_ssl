/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_dispatcher.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 10:46:12 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 14:47:45 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "message_digest.h"

static const t_sha g_sha[NB_SHA] = {
	[SHA_224] =
	{
		.cmd = SHA224,
		.digest_func = sha_32_digest,
	},
	[SHA_256] =
	{
		.cmd = SHA256,
		.digest_func = sha_32_digest,
	},
	[SHA_384] =
	{
		.cmd = SHA384,
		.digest_func = sha_64_digest,
	},
	[SHA_512] =
	{
		.cmd = SHA512,
		.digest_func = sha_64_digest,
	},
};

void		sha32_verbose(t_sha_32 sha)
{
	if (sha.flags & SHA_OARG_V_PAD || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha.padding_size + 64);
	}
	if (sha.flags & SHA_OARG_V_BLOCK || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha.block);
	}
}

void		sha64_verbose(t_sha_64 sha)
{
	if (sha.flags & SHA_OARG_V_PAD || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha.padding_size + 64);
	}
	if (sha.flags & SHA_OARG_V_BLOCK || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha.block);
	}
}

char		*sha_dispatcher(t_cmd_type cmd, unsigned char *entry,
								size_t entry_size, t_cmd_opt *opt)
{
	t_sha_algo sha_index;

	sha_index = 0;
	while (sha_index < NB_SHA)
	{
		if (cmd == g_sha[sha_index].cmd)
		{
			if (opt)
			{
				return (g_sha[sha_index].digest_func(cmd, entry, entry_size,
							opt->opts_pflag));
			}
			return (g_sha[sha_index].digest_func(cmd, entry, entry_size, 0));
		}
		sha_index++;
	}
	return (NULL);
}
