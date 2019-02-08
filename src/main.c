/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:03:01 by banthony          #+#    #+#             */
/*   Updated: 2019/02/08 19:19:01 by banthony         ###   ########.fr       */
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
	ft_putendl(" test [-p | -q | -r | -s | -help | -print [red | blue | green]]");
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
	ft_putendl("Unknow command");
}

/*
**	Pour l'instant si ac < 2, on affiche l'usage
**	plus tard, ft_ssl lira sur STDIN pour savoir quoi faire.
*/

int			main(int ac, char **av)
{
	if (ac < 2)
	{
		usage(av[0]);
		return (0);
	}
	ssl_start(ac, av);
	return (0);
}
