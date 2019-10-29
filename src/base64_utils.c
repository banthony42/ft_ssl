/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_utils.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:22:48 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:26:56 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

void	init_b64(t_base64 *b64, t_cmd_type cmd, t_cmd_opt *opt)
{
	ft_memset(b64, 0, sizeof(t_base64));
	b64->b64_url = (cmd == BASE64_URL) ? true : false;
	b64->out = STDOUT_FILENO;
	if (opt && opt->opts_flag & CIPHER_DECODE_MASK)
		b64->cipher_mode = CIPHER_DECODE;
}

int		b64decode(int value, int b64_decode[255])
{
	if (value == (int)'=')
		return (0);
	return (b64_decode[value]);
}

/*
**	Return true if all character in the entry, are present in the base64 table.
**	Return false otherwise.
*/

size_t	get_final_lenght(size_t ignore, int len, char *entry)
{
	int		i;
	size_t	equal;

	equal = 0;
	i = -1;
	while (++i < len)
		if (entry[i] == '=')
			equal++;
	return ((((size_t)len - ignore) / 4 * 3) - equal);
}

t_bool	is_valid_ciphering(char *entry, int len,
									size_t *result_len, t_bool isb64_url)
{
	int			i;
	size_t		ignore;
	char		*avoid;

	if (!entry || !result_len)
		return (false);
	avoid = (isb64_url == true) ? "-_=" : "+/=";
	i = -1;
	ignore = 0;
	while (++i < len)
		if (!ft_isalnum((int)entry[i]) && !ft_strchr(avoid, (int)entry[i]))
		{
			if (entry[i] == ' ' || entry[i] == '\n' || entry[i] == '\t')
			{
				ignore++;
				continue;
			}
			ft_putchar('\n');
			return (false);
		}
	*result_len = get_final_lenght(ignore, len, entry);
	return (true);
}
