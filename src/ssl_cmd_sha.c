/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_sha.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/10 10:25:35 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 18:59:48 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "message_digest.h"

int			usage_sha(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putstr(" [-p | -q | -r | -s");
	ft_putstr(" | -verbose [padding | block | all]");
	ft_putendl(" | -dump [padding | block | all]]");
	return (CMD_SUCCESS);
}

static void	sha_display_output(char *sha_result, char *entry,
								t_cmd_opt *opt, int is_str)
{
	char	*cmd_name;

	cmd_name = ssl_get_cmd_name(opt->cmd, true);
	if (opt->opts_flag & SHA_Q_MASK)
		ft_putendl(sha_result);
	else if (opt->opts_flag & SHA_R_MASK)
	{
		ft_putstr(sha_result);
		ft_putstr(" ");
		(is_str) ? (ft_putchar('"')) : ((void)is_str);
		ft_putstr(entry);
		(is_str) ? (ft_putstr("\"\n")) : (ft_putchar('\n'));
	}
	else
	{
		if (cmd_name)
			ft_putstr(cmd_name);
		ft_putstr("(");
		(is_str) ? (ft_putchar('"')) : ((void)is_str);
		ft_putstr(entry);
		(is_str) ? (ft_putchar('"')) : ((void)is_str);
		ft_putstr(")= ");
		ft_putendl(sha_result);
	}
	ft_strdel(&cmd_name);
}

static int	browse_argv(int ac, char **av, t_cmd_opt *opt, int i_str)
{
	int				i;
	char			*sha_dig;
	unsigned char	*entry;
	size_t			entry_size;

	if (!opt)
		return (CMD_SUCCESS);
	i = opt->end - 1;
	entry = NULL;
	while (++i < ac)
	{
		if (i != i_str)
		{
			if (!(entry = read_file(av[i], &entry_size)))
				continue ;
			sha_dig = sha_dispatcher(opt->cmd, entry, entry_size, opt);
		}
		else
			sha_dig = sha_dispatcher(opt->cmd, (unsigned char*)av[i],
				ft_strlen(av[i]), opt);
		sha_display_output(sha_dig, av[i], opt, !(i != i_str));
		ft_strdel(&sha_dig);
		ft_memdel((void**)&entry);
	}
	return (CMD_SUCCESS);
}

static void	hash_stdin(t_cmd_type cmd, t_cmd_opt *opt, char *entry, size_t size)
{
	char	*result;

	result = NULL;
	if (opt && opt->opts_flag & SHA_P_MASK)
		ft_putstr(entry);
	if (opt)
		result = sha_dispatcher(cmd, (unsigned char*)entry, size, opt);
	else
		result = sha_dispatcher(cmd, (unsigned char*)entry, size, NULL);
	if (!ft_strchr(entry, '\n'))
		ft_putchar('\n');
	ft_putendl(result);
	ft_strdel(&result);
}

int			cmd_sha(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	char	*entry;
	int		i_str;
	size_t	size;

	i_str = -2;
	entry = NULL;
	if (!opt || (opt && !opt->end) || (opt && (opt->opts_flag & SHA_P_MASK)))
	{
		if (!(entry = (char*)read_cat(STDIN_FILENO, &size)))
			return (CMD_ERROR);
		hash_stdin(cmd, opt, entry, size);
		ft_strdel(&entry);
	}
	if (opt && (opt->opts_flag & SHA_S_MASK))
		i_str = find_key(av, ac, "-s");
	if (i_str < 0)
		i_str = -2;
	if (opt && opt->end)
	{
		opt->cmd = cmd;
		browse_argv(ac, av, opt, i_str + 1);
	}
	return (CMD_SUCCESS);
}
