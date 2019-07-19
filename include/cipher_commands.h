/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   cipher_commands.h                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 12:40:36 by abara             #+#    #+#             */
/*   Updated: 2019/07/19 12:55:33 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		CIPHER_COMMANDS_H
# define	CIPHER_COMMANDS_H

# include "ft_ssl.h"

/*
**	BASE64 options & MASK
*/

# define BASE64_OPTS "-d;-e;-i;-o"
# define B64_D_MASK 1
# define B64_E_MASK 1 << 1
# define B64_I_MASK 1 << 2
# define B64_O_MASK 1 << 3

#endif
