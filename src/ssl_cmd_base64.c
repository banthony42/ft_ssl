/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_base64.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 13:06:48 by abara             #+#    #+#             */
/*   Updated: 2019/07/19 13:09:16 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int			usage_base64(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-d | -e | -i | -o]");
	return (CMD_SUCCESS);
}

int			cmd_base64(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	(void)ac;
	(void)av;
	(void)cmd;
	(void)opt;
	return (CMD_SUCCESS);
}
