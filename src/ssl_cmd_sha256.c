
/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_impl.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:38:56 by banthony          #+#    #+#             */
/*   Updated: 2019/02/11 18:59:31 by banthony         ###   ########.fr       */
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




