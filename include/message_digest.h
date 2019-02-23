/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/02/25 19:51:30 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		MESSAGE_DIGEST_H
# define	MESSAGE_DIGEST_H

# include <stdint.h>
# include "ft_ssl.h"

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
	char		*input;
	size_t		entry_size_b;
	size_t		padding_size;
	size_t		zero_padding;
	size_t		block;
	uint32_t	flags;
	char		pad[4];
}				t_md5;

typedef struct	s_md5_data
{
	uint32_t	f;
	uint32_t	i_w;
}				t_md5_data;

/*
**	MD5 function & hash
*/
void		md5_compute(uint32_t (*word)[16], uint32_t (*hash_r)[N_INDEX], t_md5_data data, int i);
char		*md5_digest(unsigned char *entry, size_t entry_size, uint32_t flags);
uint32_t	md5_func_f(uint32_t b, uint32_t c, uint32_t d);
uint32_t	md5_func_g(uint32_t b, uint32_t c, uint32_t d);
uint32_t	md5_func_h(uint32_t b, uint32_t c, uint32_t d);
uint32_t	md5_func_i(uint32_t b, uint32_t c, uint32_t d);

#endif



















