/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_key_value_parser.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 16:32:26 by banthony          #+#    #+#             */
/*   Updated: 2019/10/18 16:36:09 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

/*
**	Return the number of occurence of the character c
**	found in src.
*/

size_t			ft_strchrcount(const char *src, int c)
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
		return (false);
	lst = *alst;
	while (lst != NULL)
	{
		if (!condition(lst, new))
			return (false);
		lst = lst->next;
	}
	ft_lstadd(alst, new);
	return (true);
}

static t_bool	key_is_not_contain(t_list *elem, t_list *new)
{
	t_opt_arg *new_pair;
	t_opt_arg *elem_pair;

	if (!elem || !new)
		return (false);
	if (!elem->content || !new->content)
		return (false);
	elem_pair = (t_opt_arg*)(elem->content);
	new_pair = (t_opt_arg*)(new->content);
	if (elem_pair->key != new_pair->key)
		return (true);
	return (false);
}

/*
**	WARN: two key with different value is considere as error
*/

int				ssl_find_key_value(char *entry, char **values,
									t_opt_arg opt_arg, t_cmd_opt *opt)
{
	t_opt_arg	new_arg;
	t_list		*new;

	if (ft_tablen(values) == 1
		&& !ft_strncmp(values[0], OPT_FROM_USER, ft_strlen(values[0])))
	{
		ft_freetab(values);
		new_arg.key = opt_arg.key;
		new_arg.values = entry;
		new = ft_lstnew(&new_arg, sizeof(new_arg));
		if (!opt->flag_with_input)
			opt->flag_with_input = new;
		else if (!ft_lstadd_if(&opt->flag_with_input, new, key_is_not_contain))
		{
			ft_lstdelone(&new, free_cmd_opt);
			return (PARSING_OPT_ERROR);
		}
		return (PARSING_SUCCESS);
	}
	return (PARSING_CONTINUE);
}
