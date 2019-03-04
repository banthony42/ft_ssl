/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_sha384.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:56:20 by banthony          #+#    #+#             */
/*   Updated: 2019/02/26 19:43:10 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			usage_sha384(char *exe)
{
	ft_putstr(exe);
	ft_putstr(" sha384 [-p | -q | -r | -s");
	ft_putstr(" | -verbose [padding | block | all]");
	ft_putendl(" | -dump [padding | block | all]]");
	return (CMD_SUCCESS);
}

static void	sha384_display_output(char *sha384_result, char *entry,
								uint64_t opt, int is_str)
{
	if (opt & SHA384_Q_MASK)
		ft_putendl(sha384_result);
	else if (opt & SHA384_R_MASK)
	{
		ft_putstr(sha384_result);
		ft_putstr(" ");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putstr("\"\n");
		else
			ft_putchar('\n');
	}
	else
	{
		ft_putstr("SHA384(");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putchar('"');
		ft_putstr(")= ");
		ft_putendl(sha384_result);
	}
}

static int	browse_argv(int ac, char **av, t_cmd_opt *opts, int i_str)
{
	int				i;
	char			*sha384_result;
	unsigned char	*entry;
	size_t			entry_size;

	if (!opts)
		return (CMD_SUCCESS);
	i = opts->end - 1;
	entry = NULL;
	while (++i < ac)
	{
		if (i != i_str)
		{
			if (!(entry = read_file(av[i], &entry_size)))
				continue ;
			sha384_result = sha384_digest(entry, entry_size, opts->opts_pflag);
		}
		else
			sha384_result = sha384_digest((unsigned char*)av[i],
				ft_strlen(av[i]), opts->opts_pflag);
		sha384_display_output(sha384_result, av[i], opts->opts_flag, !(i != i_str));
		ft_strdel(&sha384_result);
		ft_memdel((void**)&entry);
	}
	return (CMD_SUCCESS);
}

static void	hash_stdin(t_cmd_opt *opt, char *entry, size_t size)
{
	char	*result;

	result = NULL;
	if (opt && opt->opts_flag & SHA384_P_MASK)
		ft_putstr(entry);
	if (opt)
		result = sha384_digest((unsigned char*)entry, size, opt->opts_pflag);
	else
		result = sha384_digest((unsigned char*)entry, size, 0);
	if (!ft_strchr(entry, '\n'))
		ft_putchar('\n');
	ft_putendl(result);
	ft_strdel(&result);
}

int			cmd_sha384(int ac, char **av, t_cmd_opt *opt)
{
	char	*entry;
	int		i_str;
	size_t	size;

	i_str = -2;
	entry = NULL;
	if (!opt || (opt && !opt->end) || (opt && (opt->opts_flag & SHA384_P_MASK)))
	{
		if (!(entry = (char*)read_cat(STDIN_FILENO, &size)))
			return (CMD_ERROR);
		hash_stdin(opt, entry, size);
		ft_strdel(&entry);
	}
	if (opt && (opt->opts_flag & SHA384_S_MASK))
		i_str = find_key(av, ac, "-s");
	if (i_str < 0)
		i_str = -2;
	if (opt && opt->end)
		browse_argv(ac, av, opt, i_str + 1);
	return (CMD_SUCCESS);
}
