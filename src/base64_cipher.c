/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_cipher.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/26 14:21:32 by abara             #+#    #+#             */
/*   Updated: 2019/07/26 14:53:09 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

void	base64_cipher(t_base64 b64, char *entry)
{
	// If file input and entry are both present,
	// determine which data will be ciphered.
	ft_putendl_fd(entry, b64.out_fd);
}
