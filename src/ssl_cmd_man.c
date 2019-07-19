/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_man.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <marvin@42.fr>                       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 15:39:25 by abara             #+#    #+#             */
/*   Updated: 2019/07/19 15:47:18 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int			usage_man(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [command]");
	return (CMD_SUCCESS);
}

int			cmd_man(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	if (ac != 3)
		usage_man("ft_ssl", "man");
	(void)ac;
	(void)av;
	(void)cmd;
	(void)opt;
	return (CMD_SUCCESS);
}
