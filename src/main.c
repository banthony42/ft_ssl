/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:03:01 by banthony          #+#    #+#             */
/*   Updated: 2019/07/19 12:38:28 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static void	usage(char **argv)
{
	// Use this line to see the entire command.
	// ft_putendl("=== <DEBUG> ===")
	// ft_printtab(argv, ft_putstr, "|");
	// ft_putendl("=== < END > ====")
	
	ft_putstr("usage:");
	ft_putstr(argv[0]);
	ft_putendl(" command [command opts] [command args]\n");
	ft_putendl("Standard commands:");
	ft_putendl("man [command]\t(wip)\n");
	ft_putendl("\nMessage Digest commands:");
	ft_putendl("md5\nsha224\nsha256\nsha384\nsha512");
	ft_putendl("sha512_224\nsha512_256\n");
	ft_putendl("Cipher commmands:");
	ft_putendl("base64\t(wip)\ndes\t(wip)\ndes-ecb\t(wip)\ndec-cbc\t(wip)");
	ft_putendl("\nTest the parser:");
	ft_putendl("test");
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
	usage(av);
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
