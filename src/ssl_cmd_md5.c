/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_md5.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:44:23 by banthony          #+#    #+#             */
/*   Updated: 2019/02/19 20:17:16 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			usage_md5(char *exe)
{
	ft_putstr(exe);
	ft_putendl(" md5 usage");
	return (CMD_SUCCESS);
}

/*
**	Code here the hash algorithm
*/

static char	*md5_digest(char *entry)
{
	(void)entry;
	return (ft_strdup("3ba35f1ea0d170cb3b9a752e3360286c"));
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
		ft_putendl(entry);
	}
	else
	{
		ft_putstr("MD5 (");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putchar('"');
		ft_putstr(") = ");
		ft_putendl(md5_result);
	}
}

static int	browse_argv(int ac, char **av, t_cmd_opt *opts, int i_str)
{
	int		i;
	int		fd;
	char	*md5_result;
	char	*entry;

	if (!opts)
		return (CMD_SUCCESS);
	i = opts->end - 1;
	entry = NULL;
	fd = 0;
	while (++i < ac)
	{
		if (i != i_str)
		{
			if (!(read_file(av[i])))
				continue ;
			md5_result = md5_digest(entry);
			if (close(fd) < 0)
				return (CMD_ERROR);
		}
		else
			md5_result = md5_digest(av[i]);
		md5_display_output(md5_result, av[i], opts->opts_flag, !(i != i_str));
		ft_strdel(&md5_result);
		ft_strdel(&entry);
	}
	return (CMD_SUCCESS);
}

/*
**	No arg	- read from stdin
**	arg > 0	- open as a file.
**	-p		- echo STDIN on STDOUT and write result on STDOUT
**	-q		- quiet mode, dont print "MD5 (arg) = "
**	-r		- reverse output
**	-s		- use argv as string to use for the checksum
**			keep in memory the s index in argv
**			index_s + 1 use as string for checksum
**			index_s + n use as file, try to open it
*/

int			cmd_md5(int ac, char **av, t_cmd_opt *opts)
{
	char	*entry;
	char	*result;
	int		i_str;

	i_str = -2;
	entry = NULL;
	result = NULL;
	if (!opts || !opts->end || (opts && (opts->opts_flag & MD5_P_MASK)))
	{
		if (!(entry = read_cat(STDIN_FILENO)))
			return (CMD_ERROR);
		if (opts && opts->opts_flag & MD5_P_MASK)
			ft_putstr(entry);
		result = md5_digest(entry);
		if (!ft_strchr(entry, '\n'))
			ft_putchar('\n');
		ft_putendl(result);
		ft_strdel(&entry);
		ft_strdel(&result);
	}
	if (opts && (opts->opts_flag & MD5_S_MASK))
		i_str = find_key(av, ac, "-s");
	if (i_str < 0)
		i_str = -2;
	browse_argv(ac, av, opts, i_str + 1);
	return (CMD_SUCCESS);
}
