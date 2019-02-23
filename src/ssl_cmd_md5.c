/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_md5.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:44:23 by banthony          #+#    #+#             */
/*   Updated: 2019/02/25 20:21:44 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			usage_md5(char *exe)
{
	ft_putstr(exe);
	ft_putstr(" md5 [-p | -q | -r | -s");
	ft_putstr(" | -verbose [padding | block | all]");
	ft_putendl(" | -dump [padding | block | all]]");
	return (CMD_SUCCESS);
}

static void	md5_display_output(char *md5_result, char *entry,
								uint32_t opt, int is_str)
{
	if (opt & MD5_Q_MASK)
		ft_putendl(md5_result);
	else if (opt & MD5_R_MASK)
	{
		ft_putstr(md5_result);
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
		ft_putstr("MD5(");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putchar('"');
		ft_putstr(")= ");
		ft_putendl(md5_result);
	}
}

static int	browse_argv(int ac, char **av, t_cmd_opt *opts, int i_str)
{
	int				i;
	char			*md5_result;
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
			md5_result = md5_digest(entry, entry_size, opts->opts_pflag);
		}
		else
			md5_result = md5_digest((unsigned char*)av[i],
				ft_strlen(av[i]), opts->opts_pflag);
		md5_display_output(md5_result, av[i], opts->opts_flag, !(i != i_str));
		ft_strdel(&md5_result);
		ft_memdel((void**)&entry);
	}
	return (CMD_SUCCESS);
}

static void	hash_stdin(t_cmd_opt *opt, char *entry, size_t size)
{
	char	*result;

	result = NULL;
	if (opt && opt->opts_flag & MD5_P_MASK)
		ft_putstr(entry);
	if (opt)
		result = md5_digest((unsigned char*)entry, size, opt->opts_pflag);
	else
		result = md5_digest((unsigned char*)entry, size, 0);
	if (!ft_strchr(entry, '\n'))
		ft_putchar('\n');
	ft_putendl(result);
	ft_strdel(&result);
}

int			cmd_md5(int ac, char **av, t_cmd_opt *opt)
{
	char	*entry;
	int		i_str;
	size_t	size;

	i_str = -2;
	entry = NULL;
	if (!opt || (opt && !opt->end) || (opt && (opt->opts_flag & MD5_P_MASK)))
	{
		if (!(entry = (char*)read_cat(STDIN_FILENO, &size)))
			return (CMD_ERROR);
		hash_stdin(opt, entry, size);
		ft_strdel(&entry);
	}
	if (opt && (opt->opts_flag & MD5_S_MASK))
		i_str = find_key(av, ac, "-s");
	if (i_str < 0)
		i_str = -2;
	if (opt && opt->end)
		browse_argv(ac, av, opt, i_str + 1);
	return (CMD_SUCCESS);
}
