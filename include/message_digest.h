/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/02/26 19:48:43 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef MESSAGE_DIGEST_H
# define MESSAGE_DIGEST_H

# include <stdint.h>
# include "ft_ssl.h"

/*
**	************************ MD5 ************************
*/

# define HASH_CONST_A 0x67452301
# define HASH_CONST_B 0xefcdab89
# define HASH_CONST_C 0x98badcfe
# define HASH_CONST_D 0x10325476

typedef enum	s_md5_register
{
	MD5_A,
	MD5_B,
	MD5_C,
	MD5_D,
	MD5_N_REGISTER,
}				t_md5_register;

typedef struct	s_md5
{
	uint32_t	hash[MD5_N_REGISTER];
	char		*input;
	size_t		entry_size_b;
	size_t		padding_size;
	size_t		zero_padding;
	size_t		block;
	uint32_t	flags;
	char		pad[4];
}				t_md5;

/*
**	Result of function - use to compute hash register
*/
typedef struct	s_md5_data
{
	uint32_t	f;
	uint32_t	i_w;
}				t_md5_data;

/*
**	MD5 function & hash
*/

void			md5_compute(uint32_t (*word)[16], uint32_t (*hash_r)[MD5_N_REGISTER], t_md5_data data, int i);
char			*md5_digest(unsigned char *entry, size_t entry_size, uint32_t flags);
uint32_t		md5_func_f(uint32_t b, uint32_t c, uint32_t d);
uint32_t		md5_func_g(uint32_t b, uint32_t c, uint32_t d);
uint32_t		md5_func_h(uint32_t b, uint32_t c, uint32_t d);
uint32_t		md5_func_i(uint32_t b, uint32_t c, uint32_t d);

/*
**	************************ SHA256 ************************
*/

typedef enum	s_sha256_register
{
	SHA256_A,
	SHA256_B,
	SHA256_C,
	SHA256_D,
	SHA256_E,
	SHA256_F,
	SHA256_G,
	SHA256_H,
	SHA256_N_REGISTER,
}				t_sha256_register;

typedef struct	s_sha256
{
	uint32_t	hash[SHA256_N_REGISTER];
	char		*input;
	size_t		entry_size_b;
	size_t		padding_size;
	size_t		zero_padding;
	size_t		block;
	uint32_t	flags;
	char		pad[4];
}				t_sha256;

/*
**	SHA256 function & hash
*/
char			*sha256_digest(unsigned char *entry, size_t entry_size, uint32_t flags);

#endif
