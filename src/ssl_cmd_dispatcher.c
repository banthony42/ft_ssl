/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_dispatcher.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:40:14 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 14:58:10 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

/*
**	Structure de parametre pour le parser, pour chaque commande.
*/
static const t_parsing_param g_ssl_cmd_parse[NB_CMD] = {
	[MD5] =
	{
		.cmd = MD5,
		.opts = MD5_OPTS,
		.opts_len = sizeof(MD5_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = MD5_OPT_ARG_VERBOSE_KEY,
			.values = MD5_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] =
		{
			.key = MD5_OPT_ARG_DUMP_KEY,
			.values = MD5_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA224] =
	{
		.cmd = SHA224,
		.opts = SHA224_OPTS,
		.opts_len = sizeof(SHA224_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = SHA224_OPT_ARG_VERBOSE_KEY,
			.values = SHA224_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] =
		{
			.key = SHA224_OPT_ARG_DUMP_KEY,
			.values = SHA224_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA256] =
	{
		.cmd = SHA256,
		.opts = SHA256_OPTS,
		.opts_len = sizeof(SHA256_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = SHA256_OPT_ARG_VERBOSE_KEY,
			.values = SHA256_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] =
		{
			.key = SHA256_OPT_ARG_DUMP_KEY,
			.values = SHA256_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA384] =
	{
		.cmd = SHA384,
		.opts = SHA384_OPTS,
		.opts_len = sizeof(SHA384_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = SHA384_OPT_ARG_VERBOSE_KEY,
			.values = SHA384_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] =
		{
			.key = SHA384_OPT_ARG_DUMP_KEY,
			.values = SHA384_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[SHA512] =
	{
		.cmd = SHA512,
		.opts = SHA512_OPTS,
		.opts_len = sizeof(SHA512_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = SHA512_OPT_ARG_VERBOSE_KEY,
			.values = SHA512_OPT_ARG_VERBOSE_VALUES,
		},
		.opts_arg[1] =
		{
			.key = SHA512_OPT_ARG_DUMP_KEY,
			.values = SHA512_OPT_ARG_DUMP_VALUES,
		},
		.opts_arg_len = 2,
	},
	[TEST] =
	{
		.cmd = TEST,
		.opts = TEST_OPTS,
		.opts_len = sizeof(TEST_OPTS) - 1,
		.opts_with_arg = true,
		.opts_arg[0] =
		{
			.key = TEST_OPT_PRINT_KEY,
			.values = TEST_OPT_PRINT_VALUES
		},
		.opts_arg[1] =
		{
			.key = TEST_OPT_ARG_KEY,
			.values = TEST_OPT_ARG_VALUES
		},
		.opts_arg_len = 2,
	}
};

/*
**	Stucture des commandes disponible, utile au dispatcher.
*/
static const t_cmd g_ssl_cmd[NB_CMD] = {
	[MD5] =
	{
		.name = "md5",
		.len = sizeof("md5") - 1,
		.func = cmd_md5,
		.usage = usage_md5,
	},
	[SHA224] =
	{
		.name = "sha224",
		.len = sizeof("sha224") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA256] =
	{
		.name = "sha256",
		.len = sizeof("sha256") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA384] =
	{
		.name = "sha384",
		.len = sizeof("sha384") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[SHA512] =
	{
		.name = "sha512",
		.len = sizeof("sha512") - 1,
		.func = cmd_sha,
		.usage = usage_sha,
	},
	[TEST] =
	{
		.name = "test",
		.len = sizeof("test") - 1,
		.func = cmd_test,
		.usage = usage_test,
	}
};

/*
**	Si le seul arguments est le nom de la commande, (ac == 2)
**	Le comportement dependera de la commande. (voir ssl_cmd_impl.c)
**	Soit STDIN sera lu pour obtenir une entree utilisateur.
**	Soit l'usage de la commande sera affichee.
**	Dans le cas ou STDIN est lu, il sera trop tard pour passer des options.
*/

int	ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd)
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
				if (error == CMD_USAGE || error == PARSING_OPT_ERROR)
					return (g_ssl_cmd[cmd].usage(av[0], g_ssl_cmd[cmd].name));
				if (error != PARSING_SUCCESS)
					return (error);
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













