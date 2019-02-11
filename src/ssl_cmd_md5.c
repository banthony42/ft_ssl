/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_md5.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:44:23 by banthony          #+#    #+#             */
/*   Updated: 2019/02/11 19:03:04 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int	usage_md5(char *exe)
{
	ft_putstr(exe);
	ft_putendl(" md5 usage");
	return (CMD_SUCCESS);
}


int	cmd_md5(int ac, char **av, t_cmd_opt *opts)
{
	ssize_t	ret = 1;
	char	*entry;
	char	buf[MAXBYTE];

	entry = NULL;
	if (!opts || !opts->end)
	{
		ft_putendl("md5 - read stdin - press Ctrl+D twice to stop read");
		while (ret)
		{
			if ((ret = read(STDIN_FILENO, buf, MAXBYTE - 1)) <= 0)
				break ;
			buf[ret] = '\0';
			ft_strjoin_replace(&entry, buf);
		}
	}
	ft_putendl("\nmd5 on:");
	if (opts && opts->end)
		ft_putendlcol(SH_GREEN, av[opts->end]);
	else
		ft_putendlcol(SH_GREEN, entry);
	ft_strdel(&entry);
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}
