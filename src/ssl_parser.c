/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_parser.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:39:03 by banthony          #+#    #+#             */
/*   Updated: 2019/02/08 17:39:28 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int	ssl_cmd_parser(int ac, char **av, t_parsing_param param, t_cmd_opt *opt)
{
	ft_putstr("parser for:");
	ft_putnbrendl(param.cmd);
	(void)ac;
	(void)av;
	(void)param;
	(void)opt;
	return (CMD_PARSING_SUCCESS);
}
