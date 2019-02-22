/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/02/22 19:34:27 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		MESSAGE_DIGEST_H
# define	MESSAGE_DIGEST_H

# include <stdint.h>

# define HASH_CONST_A 0x67452301
# define HASH_CONST_B 0xefcdab89
# define HASH_CONST_C 0x98badcfe
# define HASH_CONST_D 0x10325476

typedef enum	s_index
{
	A,
	B,
	C,
	D,
	N_INDEX,
}				t_index;

typedef struct	s_md5
{
	uint32_t	hash[N_INDEX];
	char		*output;
	char		*input;
	size_t		input_size;
	size_t		zero_padding;
}				t_md5;

#endif







