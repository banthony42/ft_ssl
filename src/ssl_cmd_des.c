/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_base64.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 13:06:48 by abara             #+#    #+#             */
/*   Updated: 2019/09/13 10:41:11 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int			usage_des(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-a | -d | -e | -i [input_file] | -k [hexa_key] | -o [output_file] | -p [ascii_pwd] | -s [hexa_salt] | -v [init_vector]]");
	return (CMD_SUCCESS);
}

int			cmd_des(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	(void)cmd;
	(void)ac;
	(void)av;
	(void)opt;
	ft_putendl("Bijoul'");
	usage_des(av[0], "des");
	return (CMD_SUCCESS);
}
