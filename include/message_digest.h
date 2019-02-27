/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/02/27 18:22:16 by banthony         ###   ########.fr       */
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

# define HASH_CONST_SHA_A 0x6a09e667//0x6a09e667
# define HASH_CONST_SHA_B 0xbb67ae85//0xbb67ae85
# define HASH_CONST_SHA_C 0x3c6ef372//0x3c6ef372
# define HASH_CONST_SHA_D 0xa54ff53a//0xa54ff53a
# define HASH_CONST_SHA_E 0x510e527f//0x510e527f
# define HASH_CONST_SHA_F 0x9b05688c//0x9b05688c
# define HASH_CONST_SHA_G 0x1f83d9ab//0x1f83d9ab
# define HASH_CONST_SHA_H 0x5be0cd19//0x5be0cd19

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
	uint32_t	Wt[64];
	uint32_t	tmp1;
	uint32_t	tmp2;
	char		pad[4];
}				t_sha256;

/*
**	SHA256 function & hash
*/
char			*sha256_digest(unsigned char *entry, size_t entry_size, uint32_t flags);
uint32_t		sha256_func_ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t		sha256_func_maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t		sha256_func_sum0(uint32_t x);
uint32_t		sha256_func_sum1(uint32_t x);
uint32_t		sha256_func_sig0(uint32_t x);
uint32_t		sha256_func_sig1(uint32_t x);

#endif
