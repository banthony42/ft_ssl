/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_dispatcher.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <marvin@42.fr>                       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 16:20:23 by abara             #+#    #+#             */
/*   Updated: 2019/09/13 11:58:48 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "message_digest.h"
#include "cipher_commands.h"

/*
**	Structure de parametre pour le parser, pour chaque commande.
*/
static const t_parsing_param g_ssl_cmd_parse[NB_CMD] = {
	[MD5] = {
		.cmd = MD5,
		.opts = MD5_OPTS,
		.opts_len = sizeof(MD5_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = MD5_OPT_ARG_VERBOSE_KEY,
			.values = MD5_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = MD5_OPT_ARG_DUMP_KEY,
			.values = MD5_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA224] = {
		.cmd = SHA224,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA256] = {
		.cmd = SHA256,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA384] = {
		.cmd = SHA384,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA512] = {
		.cmd = SHA512,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA512_256] = {
		.cmd = SHA512_256,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA512_224] = {
		.cmd = SHA512_224,
		.opts = SHA_OPTS,
		.opts_len = sizeof(SHA_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = SHA_OPT_ARG_VERBOSE_KEY,
			.values = SHA_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] = {
			.key = SHA_OPT_ARG_DUMP_KEY,
			.values = SHA_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[BASE64] = {
		.cmd = BASE64,
		.opts = CIPHER_OPTION_MODE,
		.opts_len = sizeof(CIPHER_OPTION_MODE) -1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = CIPHER_INPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[1] = {
			.key = CIPHER_OUTPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg_len = 2,
	},
	[BASE64_URL] = {
		.cmd = BASE64_URL,
		.opts = CIPHER_OPTION_MODE,
		.opts_len = sizeof(CIPHER_OPTION_MODE) -1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = CIPHER_INPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[1] = {
			.key = CIPHER_OUTPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg_len = 2,
	},
	[DES] = {
		.cmd = DES,
		.opts = DES_OPTS,
		.opts_len = sizeof(DES_OPTS) -1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = CIPHER_INPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[1] = {
			.key = CIPHER_OUTPUT_FILE_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[2] = {
			.key = DES_HEXAKEY_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[3] = {
			.key = DES_PASS_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[4] = {
			.key = DES_SALT_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg[5] = {
			.key = DES_INIT_VECTOR_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg_len = 6,
	},
	[TEST] = {
		.cmd = TEST,
		.opts = TEST_OPTS,
		.opts_len = sizeof(TEST_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] = {
			.key = TEST_OPT_PRINT_KEY,
			.values = TEST_OPT_PRINT_VALUES
		},
		.opts_arg[1] = {
			.key = TEST_OPT_ARG_KEY,
			.values = TEST_OPT_ARG_VALUES
		},
		.opts_arg[2] = {
			.key = TEST_OPT_STR_KEY,
			.values = OPT_FROM_USER,
		},
		.opts_arg_len = 3,
	},
	[MAN] = {
		.cmd = TEST,
		.opts = "",
		.opts_len = 0,
		.opts_with_arg = false,
		.opts_arg = {{NULL, NULL}},
		.opts_arg_len = 0,
	}
};

/*
**	Stucture des commandes disponible, utile au dispatcher.
**	(Nom de la commande, taille de la string,
**	fonction d'entree, fonction d'usage)
*/
static const t_cmd g_ssl_cmd[NB_CMD] = {
	[MD5] = {
		.name = "md5",
		.len = sizeof("md5") - 1,
		.func = cmd_md5,
		.usage = usage_md5,
	},
	[SHA224] = {
		.name = "sha224",
		.len = sizeof("sha224") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA256] = {
		.name = "sha256",
		.len = sizeof("sha256") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA384] = {
		.name = "sha384",
		.len = sizeof("sha384") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA512] = {
		.name = "sha512",
		.len = sizeof("sha512") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA512_256] = {
		.name = "sha512_256",
		.len = sizeof("sha512_256") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA512_224] = {
		.name = "sha512_224",
		.len = sizeof("sha512_224") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[BASE64] = {
		.name = "base64",
		.len = sizeof("base64") - 1,
		.func = cmd_base64,
		.usage = usage_base64,
	},
	[BASE64_URL] = {
		.name = "base64_url",
		.len = sizeof("base64_url") - 1,
		.func = cmd_base64,
		.usage = usage_base64,
	},
	[DES] = {
		.name = "des",
		.len = sizeof("des") - 1,
		.func = cmd_des,
		.usage = usage_des,
	},
	[TEST] = {
		.name = "test",
		.len = sizeof("test") - 1,
		.func = cmd_test,
		.usage = usage_test,
	},
	[MAN] = {
		.name = "man",
		.len = sizeof("man") - 1,
		.func = cmd_man,
		.usage = usage_man,
	}
};

/*
**	Si le seul arguments est le nom de la commande, (ac == 2)
**	Le comportement dependera de la commande. (voir ssl_cmd_impl.c)
**	Soit STDIN sera lu pour obtenir une entree utilisateur.
**	Soit l'usage de la commande sera affichee.
**	Dans le cas ou STDIN est lu, il sera trop tard pour passer des options.
*/

int		ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd)
{
	size_t		entry_cmd_len;
	int			error;
	t_cmd_opt	cmd_opt;

	entry_cmd_len = ft_strlen(av[1]);
	ft_memset(&cmd_opt, 0, sizeof(cmd_opt));
	if (!ft_strncmp(av[1], g_ssl_cmd[cmd].name, entry_cmd_len))
	{
		if (entry_cmd_len == g_ssl_cmd[cmd].len)
		{
			cmd_opt.cmd = cmd;
			if (ac > 2)
			{
				error = ssl_cmd_parser(ac, av, g_ssl_cmd_parse[cmd], &cmd_opt);
				if (error == CMD_USAGE || error == PARSING_OPT_ERROR) {
					ft_lstdel(&cmd_opt.flag_with_input, free_cmd_opt);
					return (g_ssl_cmd[cmd].usage(av[0], g_ssl_cmd[cmd].name));
				}
				if (error != PARSING_SUCCESS) {
					ft_lstdel(&cmd_opt.flag_with_input, free_cmd_opt);
					return (error);
				}
				return (g_ssl_cmd[cmd].func(ac, av, cmd, &cmd_opt));
			}
			else
				return (g_ssl_cmd[cmd].func(ac, av, cmd, NULL));
		}
	}
	return (CMD_MISMATCH);
}

char	*ssl_get_cmd_name(t_cmd_type cmd, t_bool toupper)
{
	char	*name;
	size_t	i;

	i = 0;
	name = NULL;
	if (toupper)
	{
		if (!(name = ft_strdup(g_ssl_cmd[cmd].name)))
			return (NULL);
		while (i < g_ssl_cmd[cmd].len)
		{
			name[i] = (char)ft_toupper((int)name[i]);
			i++;
		}
		return (name);
	}
	return (g_ssl_cmd[cmd].name);
}

void	sha_512_224_last_hash(char (*footprint)[512 + 1], uint64_t hash)
{
	uint32_t	reg32;
	uint64_t	swapped_hash;
	char		*hash_str;

	hash_str = NULL;
	swapped_hash = (uint64_t)((hash << 32) | (hash >> 32));
	ft_memcpy(&reg32, &swapped_hash, sizeof(uint32_t));
	hash_str = ft_itoa_base_uint32(reg32, 16);
	ft_strncpy(&(*footprint)[3 * 16], hash_str, 8);
	(*footprint)[(3 * 16) + 8] = '\0';
	ft_strdel(&hash_str);
}
