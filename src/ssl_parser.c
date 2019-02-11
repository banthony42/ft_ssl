/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_parser.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:39:03 by banthony          #+#    #+#             */
/*   Updated: 2019/02/11 18:29:00 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static size_t	ft_strchrcount(const char *src, int c)
{
	int		i;
	size_t	count;

	count = 0;
	i = -1;
	if (!src || c < 0)
		return (count);
	while (src[++i] != '\0')
		if (src[i] == c)
			count++;
	if (src[i] == c)
		count++;
	return (count);
}

static int		ssl_parse_param_values(char *entry, int index,
								t_cmd_opt *opt, t_parsing_param param)
{
	int		i;
	size_t	shift;
	char	**values;
	size_t	entry_len;

	i = -1;
	shift = 0;
	entry_len = ft_strlen(entry);
	if (!(values = ft_strsplit(param.opts_arg[index].values, ';')))
		return (PARSING_FAILURE);
	while (++i < index)
		shift += ft_strchrcount(param.opts_arg[i].values, ';') + 1;
	i = -1;
	while (values[++i])
		if (!(ft_strncmp(entry, values[i], entry_len)))
		{
			if (entry_len == ft_strlen(values[i]))
			{
				opt->opts_param_flag |= (1 << (shift + (size_t)i));
				return (PARSING_SUCCESS);
			}
		}
	ft_freetab(values);
	return (PARSING_OPT_ERROR);
}

static int		ssl_parse_param_options(char *entry, int index,
								t_cmd_opt *opt, t_parsing_param param)
{
	int		i;
	size_t	entry_len;

	i = -1;
	entry_len = ft_strlen(entry);
	if (index >= 0)
		return (ssl_parse_param_values(entry, index, opt, param));
	while (index < 0 && ++i < (int)param.opts_arg_len)
		if (!ft_strncmp(entry, param.opts_arg[i].key, entry_len))
		{
			if (entry_len == ft_strlen(param.opts_arg[i].key))
				return (i);
		}
	return (PARSING_OPT_ERROR);
}

static int		ssl_parse_options(char *entry, char **options,
								t_cmd_opt *opt, t_parsing_param param)
{
	int		i;
	size_t	entry_len;

	i = -1;
	if (entry[0] != '-')
		return (PARSING_NOTAN_OPT);
	entry_len = ft_strlen(entry);
	while (options[++i])
	{
		if (!ft_strncmp(entry, options[i], entry_len))
		{
			if (ft_strlen(options[i]) == entry_len)
			{
				opt->opts_flag |= (1 << i);
				return (PARSING_SUCCESS);
			}
		}
	}
	if (param.opts_with_arg == true)
		return (ssl_parse_param_options(entry, -1, opt, param));
	return (PARSING_OPT_ERROR);
}

int				ssl_cmd_parser(int ac, char **av, t_parsing_param param,
								t_cmd_opt *opt)
{
	int		i;
	int		status;
	char	**options;

	if (!(options = ft_strsplit(param.opts, ';')) || !opt || !av)
		return (PARSING_FAILURE);
	opt->end = 0;
	i = 1;
	status = PARSING_FAILURE;
	while (++i < ac && av[i] && opt->end == 0)
	{
		if (status >= 0)
			status = ssl_parse_param_options(av[i], status, opt, param);
		else if ((status = ssl_parse_options(av[i], options, opt, param)) >= 0)
			continue ;
		if (status == PARSING_OPT_ERROR || status == PARSING_FAILURE)
			break ;
		else if (status == PARSING_NOTAN_OPT)
			opt->end = i;
	}
	ft_freetab(options);
	(status >= 0) ? (status = PARSING_OPT_ERROR) : (status += 0);
	(status == PARSING_NOTAN_OPT) ? (status = PARSING_SUCCESS) : (status += 0);
	return (status);
}
