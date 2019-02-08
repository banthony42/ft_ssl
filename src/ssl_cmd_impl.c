/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_impl.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 17:38:56 by banthony          #+#    #+#             */
/*   Updated: 2019/02/09 12:03:14 by abara            ###   ########.fr       */
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

#include <stdlib.h>
static char *decimal_to_binary(int n)
{
	int c, d, count;char *pointer;

	count = 0;
	pointer = ft_strnew(32+1);

	if (pointer == NULL)
		exit(EXIT_FAILURE);

	for (c = 31 ; c >= 0 ; c--)
	{
		d = n >> c;

		if (d & 1)
			*(pointer+count) = 1 + '0';
		else
			*(pointer+count) = 0 + '0';

		count++;
	}
	*(pointer+count) = '\0';
	ft_putendl(pointer);
	ft_strdel(&pointer);
	return  pointer;
}

int	cmd_test(int ac, char **av, t_cmd_opt *opts)
{
	if (!opts)
	{
		ft_putendl("test - read stdin");
		return (0);
	}
	ft_putendl("------------------- TEST -------------------");
	ft_putendl("-------------- Options Simple --------------");
	ft_print_memory(&opts->opts_flag, sizeof(uint32_t));
	decimal_to_binary((int)opts->opts_flag);
	if (opts->opts_flag & TEST_P_MASK)
		ft_putendlcol(SH_PINK, "P");
	if (opts->opts_flag & TEST_Q_MASK)
		ft_putendlcol(SH_PINK, "Q");
	if (opts->opts_flag & TEST_R_MASK)
		ft_putendlcol(SH_PINK, "R");
	if (opts->opts_flag & TEST_S_MASK)
		ft_putendlcol(SH_PINK, "S");
	if (opts->opts_flag & TEST_HELP_MASK)
		ft_putendlcol(SH_PINK, "HELP");
	ft_putendl("----------- Options Parametrable -----------");
	ft_print_memory(&opts->opts_arg_flag, sizeof(uint32_t));
	decimal_to_binary((int)opts->opts_arg_flag);
	if (opts->opts_arg_flag & TEST_PRINT_RED_MASK)
		ft_putendlcol(SH_RED, "PRINT RED");
	if (opts->opts_arg_flag & TEST_PRINT_GREEN_MASK)
		ft_putendlcol(SH_GREEN, "PRINT GREEN");
	if (opts->opts_arg_flag & TEST_PRINT_BLUE_MASK)
		ft_putendlcol(SH_BLUE, "PRINT BLUE");
	if (opts->opts_arg_flag & TEST_ARG_VALUE1_MASK)
		ft_putendlcol(SH_PINK, "VALUE1");
	if (opts->opts_arg_flag & TEST_ARG_VALUE2_MASK)
		ft_putendlcol(SH_PINK, "VALUE2");
	if (opts->opts_arg_flag & TEST_ARG_VALUEX_MASK)
		ft_putendlcol(SH_PINK, "VALUEX");
	ft_putendl("----------------- FIN TEST -----------------");
	(void)ac;
	(void)av;
	return (CMD_SUCCESS);
}
