/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:03:01 by banthony          #+#    #+#             */
/*   Updated: 2019/02/22 12:39:44 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static void	usage(char *cmd)
{
	ft_putstr("usage:");
	ft_putstr(cmd);
	ft_putendl(" command [command opts] [command args]");
	ft_putendl("\nMessage Digest commands:");
	ft_putendl("md5");
	ft_putendl("sha256");
	ft_putendl("\nTest the parser with test command:");
	ft_putstr(cmd);
	ft_putstr(" test [-p | -q | -r | -s | -help | -print [red | blue | green]");
	ft_putendl(" | -arg [value1 | value2 | valueX]]");
}

static void	ssl_start(int ac, char **av)
{
	int			status;
	t_cmd_type	cmd;

	cmd = 0;
	while (cmd < NB_CMD)
	{
		if ((status = ssl_cmd_dispatcher(ac, av, cmd)) != CMD_MISMATCH)
		{
			if (status != CMD_SUCCESS)
				ft_putendl("cmd error");
			return ;
		}
		cmd++;
	}
	usage(av[0]);
}

int			main(int ac, char **av)
{
	int		ret;
	char	*line;
	char	*exe_with_entry;
	char	**user_entry;

	line = NULL;
	ret = 1;
	while (ac < 2 && ret > 0)
	{
		ft_putstrcol(SH_GREEN, "ft_SSL>");
		if ((ret = get_next_line(STDIN_FILENO, &line)) < 0)
		{
			ft_putendlcol(SH_RED, "GNL ERROR");
			break ;
		}
		exe_with_entry = ft_strjoin("./ft_ssl ", line);
		user_entry = ft_strsplit(exe_with_entry, ' ');
		ssl_start((int)ft_tablen(user_entry), user_entry);
		ft_strdel(&exe_with_entry);
		ft_strdel(&line);
		ft_freetab(user_entry);
	}
	if (ac >= 2)
		ssl_start(ac, av);
	return (0);
}
