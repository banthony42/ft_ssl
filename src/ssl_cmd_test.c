/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_test.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:35:46 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:59:20 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int				usage_test(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putstr(" [-p | -q | -r | -s");
	ft_putstr(" | -string \"[type something]\"");
	ft_putstr(" | -print [red | blue | green]]");
	ft_putendl(" | -arg [value1 | value2 | valueX]]");
	return (CMD_SUCCESS);
}

static void		display_flag_with_input(t_list *opt_elem)
{
	t_opt_arg *flag_with_input;

	flag_with_input = (t_opt_arg*)(opt_elem->content);
	ft_putstrcol(SH_RED, "KEY:");
	ft_putstr(flag_with_input->key);
	ft_putstrcol(SH_GREEN, " VALUE:");
	ft_putendl(flag_with_input->values);
}

static t_bool	display_cmd_composition(int ac, char **av, t_cmd_opt *opts)
{
	int i;

	ft_putendl("-------------- Arg for command -------------");
	ft_putstrcol(SH_YELLOW, "args:");
	if (!opts->end)
	{
		ft_putendlcol(SH_YELLOW, " none");
		ft_lstdel(&opts->flag_with_input, free_cmd_opt);
		return (true);
	}
	i = -1;
	while (++i < ac)
	{
		if (i >= opts->end)
			ft_putstrcol(SH_GREEN, av[i]);
		else
			ft_putstrcol(SH_YELLOW, av[i]);
		ft_putchar('|');
	}
	ft_putchar('\n');
	return (false);
}

int				cmd_test(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts)
{
	char	*entry;
	size_t	size;

	(void)cmd;
	if (!opts)
	{
		entry = NULL;
		if (!opts || !opts->end)
		{
			if (!(entry = (char*)read_cat(STDIN_FILENO, &size)))
				return (CMD_ERROR);
			ft_putstrcol(SH_GREEN, "FROM STDIN:");
			ft_putendl(entry);
			ft_strdel(&entry);
		}
		return (0);
	}
	display_options(opts);
	display_param_options(opts);
	ft_lstiter(opts->flag_with_input, display_flag_with_input);
	if (display_cmd_composition(ac, av, opts))
		return (CMD_SUCCESS);
	ft_lstdel(&opts->flag_with_input, free_cmd_opt);
	return (CMD_SUCCESS);
}
