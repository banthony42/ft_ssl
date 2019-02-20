/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/02/20 20:34:43 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		MESSAGE_DIGEST_H
# define	MESSAGE_DIGEST_H

# include <stdint.h>

typedef struct	s_md5
{
	uint32_t	register_a;
	uint32_t	register_b;
	uint32_t	register_c;
	uint32_t	register_d;
	uint32_t	sin_const[64];
	char		*output;
}				t_md5;

#endif
