/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_base64.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 13:06:48 by abara             #+#    #+#             */
/*   Updated: 2019/07/19 18:50:57 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int			usage_base64(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-d | -e | -i | -o]");
	return (CMD_SUCCESS);
}

static void display_flag_with_input(t_list *opt_elem)
{
	t_opt_arg *flag_with_input;

	flag_with_input = (t_opt_arg*)(opt_elem->content);
	ft_putstrcol(SH_RED, "KEY:");
	ft_putstr(flag_with_input->key);
	ft_putstrcol(SH_GREEN, " VALUE:");
	ft_putendl(flag_with_input->values);
}

int			base64_end(t_cmd_opt *opt, int error)
{
	ft_lstdel(&opt->flag_with_input, free_cmd_opt);
	return (error);
}

static void	ft_lstiter_with(t_list *lst, void *data, void (*f)(t_list *elem, void *data))
{
	while (lst != NULL)
	{
		f(lst, data);
		lst = lst->next;
	}
}

void		define_in_out(t_list *flag_input, void *base64_data)
{
	t_base64	*b64;
	t_opt_arg	*key_value;

	if (!flag_input || !base64_data)
		return ;
	b64 = (t_base64*)base64_data;
	key_value = (t_opt_arg*)flag_input->content;
	(void)key_value;
	(void)b64;
}

int			cmd_base64(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	t_base64	base64;
	char		*entry;
	size_t		size;

	entry = NULL;
	ft_memset(&base64, 0, sizeof(base64));
	base64.out_fd = STDOUT_FILENO;
	if (opt && opt->opts_flag & B64_DECODE_MASK)
		base64.cipher_mode = DECODE;
	if (opt && opt->flag_with_input)
		ft_lstiter_with(opt->flag_with_input, &base64, define_in_out);
	// Check opt->str_from_user: eventuel fichier input/output
	// si input == fichier valide, ne pas lire STDIN
	// si invalide erreur
	// si output file, faire un open et utiliser cet fd en sortie
	// si file existe erreur
	if (!opt || !opt->end)
	{
		if (!(entry = (char*)read_cat(STDIN_FILENO, &size)))
			return base64_end(opt, CMD_ERROR);
		ft_strdel(&entry);
	}
	ft_putendlcol(SH_GREEN, av[opt->end]);
	ft_lstiter(opt->flag_with_input, display_flag_with_input);
	ft_lstdel(&opt->flag_with_input, free_cmd_opt);
	(void)ac;
	(void)av;
	(void)cmd;
	(void)opt;
	return (CMD_SUCCESS);
}
