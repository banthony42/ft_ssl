/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_parser.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:58:58 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 15:04:50 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static void	decimal_to_binary(int n)
{
	int		c;
	int		count;
	char	result[33];

	count = 0;
	ft_memset(result, 0, 33);
	c = 31;
	while (c >= 0)
	{
		if ((n >> c) & 1)
			result[31 - c] = '1';
		else
			result[31 - c] = '0';
		count++;
		c--;
	}
	ft_putendl(result);
}

void		display_options(t_cmd_opt *opts)
{
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
}

void		display_param_options(t_cmd_opt *opts)
{
	ft_putendl("----------- Options Parametrable -----------");
	ft_print_memory(&opts->opts_pflag, sizeof(uint32_t));
	decimal_to_binary((int)opts->opts_pflag);
	if (opts->opts_pflag & TEST_PRINT_RED_MASK)
		ft_putendlcol(SH_RED, "PRINT RED");
	if (opts->opts_pflag & TEST_PRINT_GREEN_MASK)
		ft_putendlcol(SH_GREEN, "PRINT GREEN");
	if (opts->opts_pflag & TEST_PRINT_BLUE_MASK)
		ft_putendlcol(SH_BLUE, "PRINT BLUE");
	if (opts->opts_pflag & TEST_ARG_VALUE1_MASK)
		ft_putendlcol(SH_PINK, "VALUE1");
	if (opts->opts_pflag & TEST_ARG_VALUE2_MASK)
		ft_putendlcol(SH_PINK, "VALUE2");
	if (opts->opts_pflag & TEST_ARG_VALUEX_MASK)
		ft_putendlcol(SH_PINK, "VALUEX");
}
