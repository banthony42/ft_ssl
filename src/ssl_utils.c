/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:54:21 by banthony          #+#    #+#             */
/*   Updated: 2019/10/18 15:42:17 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			open_file(const char *file, int flags, char *error)
{
	int fd;

	if ((fd = open(file, flags, S_IRWXU)) < 0)
		ft_putendl(error);
	return (fd);
}

/*
**	Iteration on t_list while function return true.
*/

void		ft_lstiter_while_true(t_list *lst, void *data,
									t_list_condition condition)
{
	while (lst != NULL)
	{
		if (condition(lst, data) == false)
			break ;
		lst = lst->next;
	}
}

void		free_cmd_opt(void *opt, size_t opt_size)
{
	ft_memdel(&opt);
	(void)opt_size;
}

int			find_key(char **av, int ac, char *key)
{
	int i;

	i = -1;
	while (++i < ac)
	{
		if (av[i] && !ft_strncmp(av[i], key, ft_strlen(key)))
			return (i);
	}
	return (-1);
}
