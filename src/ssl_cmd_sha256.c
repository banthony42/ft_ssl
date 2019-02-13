/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_sha256.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:56:20 by banthony          #+#    #+#             */
/*   Updated: 2019/02/19 19:56:28 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int	usage_sha256(char *exe)
{
	ft_putstr(exe);
	ft_putendl("sha256 usage");
	return (CMD_SUCCESS);
}

int	cmd_sha256(int ac, char **av, t_cmd_opt *opts)
{
	if (!opts)
	{
		ft_putendl("sha256 - read stdin");
		return (CMD_SUCCESS);
	}
	ft_putendl("SHA256");
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}
