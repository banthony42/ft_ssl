/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_parser.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:39:03 by banthony          #+#    #+#             */
/*   Updated: 2019/07/26 13:59:03 by abara            ###   ########.fr       */
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

/*
**	Iterate on the list, passing all element to the condition function.
**	The new element will be added only if all condition calls return true.
*/
static t_bool	ft_lstadd_if(t_list **alst, t_list *new,
							 t_bool (*condition)(t_list *elem, t_list *new))
{
	t_list *lst;

	if (!alst || !new)
		return false;
	lst = *alst;
	while (lst != NULL)
	{
		if (!condition(lst, new))
			return false;
		lst = lst->next;
	}
	ft_lstadd(alst, new);
	return true;
}

static t_bool	key_is_not_contain(t_list *elem, t_list *new)
{
	t_opt_arg *new_pair;
	t_opt_arg *elem_pair;

	if (!elem || !new)
		return false;
	if (!elem->content || !new->content)
		return false;
	elem_pair = (t_opt_arg*)(elem->content);
	new_pair = (t_opt_arg*)(new->content);
	if (elem_pair->key != new_pair->key)
		return true;
	return false;
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

	// ********* *************
	t_opt_arg new_arg;
	t_list *new;
	// opt from user tablen will be always equal to 1
	if (ft_tablen(values) == 1 && !ft_strncmp(values[0], OPT_FROM_USER, ft_strlen(values[0])))
	{
		ft_freetab(values);
		new_arg.key = param.opts_arg[index].key;
		new_arg.values = entry;
		new = ft_lstnew(&new_arg, sizeof(new_arg));
		if (!opt->flag_with_input)
			opt->flag_with_input = new;
		else
		{
			// WARN: two key with different value is considere as error
			if (!ft_lstadd_if(&opt->flag_with_input, new, key_is_not_contain))
			{
				ft_lstdelone(&new, free_cmd_opt);
				return (PARSING_OPT_ERROR);
			}
		}
		return (PARSING_SUCCESS);
	}
	// ********* *************

	while (++i < index)
		shift += ft_strchrcount(param.opts_arg[i].values, ';') + 1;
	i = -1;
	while (values[++i])
		if (!(ft_strncmp(entry, values[i], entry_len)))
		{
			if (entry_len == ft_strlen(values[i]))
			{
				opt->opts_pflag |= (1 << (shift + (size_t)i));
				ft_freetab(values);
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
