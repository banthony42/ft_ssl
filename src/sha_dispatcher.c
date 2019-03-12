/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_dispatcher.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 10:46:12 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 20:29:40 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "message_digest.h"

static const t_sha g_sha[NB_SHA] = {
	[SHA_224] = {
		.cmd = SHA224,
		.digest_func = sha_32_digest,
	},
	[SHA_256] = {
		.cmd = SHA256,
		.digest_func = sha_32_digest,
	},
	[SHA_384] = {
		.cmd = SHA384,
		.digest_func = sha_64_digest,
	},
	[SHA_512] = {
		.cmd = SHA512,
		.digest_func = sha_64_digest,
	},
	[SHA_512_256] = {
		.cmd = SHA512_256,
		.digest_func = sha_64_digest,
	},
	[SHA_512_224] = {
		.cmd = SHA512_224,
		.digest_func = sha_64_digest,
	},
};

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
