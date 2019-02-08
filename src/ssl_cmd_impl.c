/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_impl.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:38:56 by banthony          #+#    #+#             */
/*   Updated: 2019/02/08 17:46:48 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int	usage_md5(void)
{
	ft_putendl("md5 usage");
	return (CMD_USAGE);
}

int	usage_sha256(void)
{
	ft_putendl("sha256 usage");
	return (CMD_USAGE);
}

int	usage_test(void)
{
	ft_putendl("test usage");
	return (CMD_USAGE);
}

int	cmd_md5(int ac, char **av, t_cmd_opt *opts)
{
	if (!opts)
	{
		ft_putendl("md5 - read stdin");
		return (0);
	}
	ft_putendl("MD5");
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}

int	cmd_sha256(int ac, char **av, t_cmd_opt *opts)
{
	if (!opts)
	{
		ft_putendl("sha256 - read stdin");
		return (0);
	}
	ft_putendl("SHA256");
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}

int	cmd_test(int ac, char **av, t_cmd_opt *opts)
{
	if (!opts)
	{
		ft_putendl("test - read stdin");
		return (0);
	}
	ft_putendl("TEST");
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}
