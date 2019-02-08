/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_parser.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:39:03 by banthony          #+#    #+#             */
/*   Updated: 2019/02/10 13:49:56 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

/*
**	Gestion d'erreur restante
**	./ft_ssl -print red -print
**	./ft_ssl -p -z -print red
**	./ft_ssl -print red -nimportequoi
*/
static int check_arg(char **arg, char **entry, int entry_c, size_t *shift)
{
	int i;
	char **value;

	if (ft_tablen(arg) < 2 || entry_c < 2)
		return (ARG_NOTFOUND);
	if (ft_strncmp(entry[0], arg[0], ft_strlen(entry[0])))
		return (ARG_NOTFOUND);
	if (ft_strlen(entry[0]) != ft_strlen(arg[0]))
		return (ARG_NOTFOUND);
	if (!(value = ft_strsplit(arg[1], ';')))
		return (ARG_ERROR);
	i = -1;
	*shift += ft_tablen(value);
	while (value[++i])
	{
		if (!ft_strncmp(entry[1], value[i], ft_strlen(entry[1])))
		{
			if (ft_strlen(entry[1]) == ft_strlen(value[i]))
			{
				ft_freetab(value);
				return (i);
			}
		}
	}
	ft_freetab(value);
	return (ARG_VALUE_NOTFOUND);
}

static int ssl_cmd_parse_arg(int ac, char **av, t_parsing_param param, t_cmd_opt *opt)
{
	int		i;
	int		error;
	size_t	i_arg;
	char	**arg;
	size_t	shift;

	i = 0;
	arg = NULL;
	while (av[++i] && i < ac)
	{
		i_arg = 0;
		shift = 0;
		while (i_arg < param.opts_arg_len)
		{
			if (!(arg = ft_strsplit(param.opts_arg[i_arg].str, ':')))
				return (CMD_PARSING_FAILURE);
			error = check_arg(arg, &av[i], ac - i, &shift);
			ft_freetab(arg);
			if (error == ARG_ERROR || error == ARG_VALUE_NOTFOUND)
				return (CMD_PARSING_FAILURE);
			else if (error != ARG_NOTFOUND)
			{
				(i_arg == 0) ? (opt->opts_arg_flag |= (1 << error))
						: (opt->opts_arg_flag |= 1 << (shift + (size_t)error));
				break ;
			}
			i_arg++;
		}
	}
	return (CMD_PARSING_SUCCESS);
}

int	ssl_cmd_parser(int ac, char **av, t_parsing_param param, t_cmd_opt *opt)
{
	int		i;
	char	**options;

	i = 0;
	if (!(options = ft_strsplit(param.opts, ';')))
		return (CMD_PARSING_FAILURE);
	while (av[++i] && i < ac)
	{
		opt->end = -1;
		while (options[++opt->end] && i < ac)
			if (!ft_strncmp(av[i], options[opt->end], ft_strlen(av[i])))
			{
				if (ft_strlen(options[opt->end]) == ft_strlen(av[i]))
				{
					opt->opts_flag |= (1 << opt->end);
					break ;
				}
			}
	}
	ft_freetab(options);
	if (param.opts_with_arg == true)
		return (ssl_cmd_parse_arg(ac, av, param, opt));
	return (CMD_PARSING_SUCCESS);
}
