/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_base64.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 13:06:48 by abara             #+#    #+#             */
/*   Updated: 2019/10/31 14:53:37 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int					usage_base64(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-d | -e | -i | -o]");
	return (CMD_SUCCESS);
}

static int			base64_end(t_base64 b64, t_cmd_opt *opt,
								int error, char *mess)
{
	if (mess)
		ft_putendl(mess);
	if (opt)
		ft_lstdel(&opt->flag_with_input, free_cmd_opt);
	if (b64.in != STDIN_FILENO && b64.in > 0)
		ft_close(b64.in);
	if (b64.out != STDOUT_FILENO && b64.out > 0)
		ft_close(b64.out);
	return (error);
}

static t_bool		define_input(t_list *flag_input, void *base64_data)
{
	t_base64	*b64;
	t_opt_arg	*flag;

	if (!flag_input || !base64_data)
		return (false);
	b64 = (t_base64*)base64_data;
	flag = (t_opt_arg*)flag_input->content;
	if (!flag->key || !flag->values)
		return (false);
	if (!ft_strcmp(flag->key, CIPHER_INPUT_FILE_KEY))
		b64->in = open_file(flag->values, O_RDONLY,
							"No such file or directory");
	if (b64->in < 0)
		return (false);
	return (true);
}

static t_bool		define_output(t_list *flag_input, void *base64_data)
{
	t_base64	*b64;
	t_opt_arg	*flag;

	if (!flag_input || !base64_data)
		return (false);
	b64 = (t_base64*)base64_data;
	flag = (t_opt_arg*)flag_input->content;
	if (!flag->key || !flag->values || b64->in < 0)
		return (false);
	if (!ft_strcmp(flag->key, CIPHER_OUTPUT_FILE_KEY))
		b64->out = open_file(flag->values, O_CREAT | O_EXCL | O_RDWR,
								"File already exist");
	if (b64->out < 0)
		return (false);
	return (true);
}

int					cmd_base64(int ac, char **av, t_cmd_type cmd,
								t_cmd_opt *opt)
{
	t_base64	base64;
	char		*entry;
	size_t		size;

	entry = NULL;
	init_b64(&base64, cmd, opt);
	if (opt && opt->flag_with_input)
	{
		if (opt->end > 0 && (ac - 1) > opt->end)
			return (base64_end(base64, opt, CMD_ERROR, B64_INPUT_ERROR));
		ft_lstiter_while_true(opt->flag_with_input, &base64, define_input);
		ft_lstiter_while_true(opt->flag_with_input, &base64, define_output);
	}
	if (base64.in < 0 || base64.out < 0)
		return (base64_end(base64, opt, CMD_ERROR, NULL));
	if (!opt || !opt->end)
	{
		if (!(entry = (char*)read_cat(base64.in, &size)))
			return (base64_end(base64, opt, CMD_ERROR, "Can't read input."));
		base64_cipher(&base64, entry, size);
		ft_strdel(&entry);
		return (base64_end(base64, opt, CMD_SUCCESS, NULL));
	}
	base64_cipher(&base64, av[opt->end], ft_strlen(av[opt->end]));
	return (base64_end(base64, opt, CMD_SUCCESS, NULL));
}
