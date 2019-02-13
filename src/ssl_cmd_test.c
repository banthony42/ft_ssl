/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_test.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:35:46 by banthony          #+#    #+#             */
/*   Updated: 2019/02/19 20:01:31 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			usage_test(char *exe)
{
	ft_putstr(exe);
	ft_putstr(" test [-p | -q | -r | -s | -help");
	ft_putstr(" | -print [red | blue | green]]");
	ft_putendl(" | -arg [value1 | value2 | valueX]]");
	return (CMD_SUCCESS);
}

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

static void	display_options(t_cmd_opt *opts)
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

static void	display_param_options(t_cmd_opt *opts)
{
	ft_putendl("----------- Options Parametrable -----------");
	ft_print_memory(&opts->opts_param_flag, sizeof(uint32_t));
	decimal_to_binary((int)opts->opts_param_flag);
	if (opts->opts_param_flag & TEST_PRINT_RED_MASK)
		ft_putendlcol(SH_RED, "PRINT RED");
	if (opts->opts_param_flag & TEST_PRINT_GREEN_MASK)
		ft_putendlcol(SH_GREEN, "PRINT GREEN");
	if (opts->opts_param_flag & TEST_PRINT_BLUE_MASK)
		ft_putendlcol(SH_BLUE, "PRINT BLUE");
	if (opts->opts_param_flag & TEST_ARG_VALUE1_MASK)
		ft_putendlcol(SH_PINK, "VALUE1");
	if (opts->opts_param_flag & TEST_ARG_VALUE2_MASK)
		ft_putendlcol(SH_PINK, "VALUE2");
	if (opts->opts_param_flag & TEST_ARG_VALUEX_MASK)
		ft_putendlcol(SH_PINK, "VALUEX");
}

int			cmd_test(int ac, char **av, t_cmd_opt *opts)
{
	int i;

	if (!opts)
		return (0);
	display_options(opts);
	display_param_options(opts);
	ft_putendl("-------------- Arg for command -------------");
	ft_putstrcol(SH_YELLOW, "args:");
	if (!opts->end)
	{
		ft_putendlcol(SH_YELLOW, " none");
		return (CMD_SUCCESS);
	}
	i = -1;
	while (++i < ac)
	{
		if (i >= opts->end)
			ft_putstrcol(SH_GREEN, av[i]);
		else
			ft_putstrcol(SH_YELLOW, av[i]);
		ft_putchar('|');
	}
	ft_putchar('\n');
	return (CMD_SUCCESS);
}
