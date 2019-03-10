/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 19:15:12 by banthony         ###   ########.fr       */
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
**	************************ SHA ************************
*/

/*
**	SHA256 Init register
*/
# define HASH_CONST_SHA256_A 0x6a09e667//0x6a09e667
# define HASH_CONST_SHA256_B 0xbb67ae85//0xbb67ae85
# define HASH_CONST_SHA256_C 0x3c6ef372//0x3c6ef372
# define HASH_CONST_SHA256_D 0xa54ff53a//0xa54ff53a
# define HASH_CONST_SHA256_E 0x510e527f//0x510e527f
# define HASH_CONST_SHA256_F 0x9b05688c//0x9b05688c
# define HASH_CONST_SHA256_G 0x1f83d9ab//0x1f83d9ab
# define HASH_CONST_SHA256_H 0x5be0cd19//0x5be0cd19

/*
**	SHA224 Init register
*/
# define HASH_CONST_SHA224_A 0xc1059ed8//0xc1059ed8
# define HASH_CONST_SHA224_B 0x367cd507//0x367cd507
# define HASH_CONST_SHA224_C 0x3070dd17//0x3070dd17
# define HASH_CONST_SHA224_D 0xf70e5939//0xf70e5939
# define HASH_CONST_SHA224_E 0xffc00b31//0xffc00b31
# define HASH_CONST_SHA224_F 0x68581511//0x68581511
# define HASH_CONST_SHA224_G 0x64f98fa7//0x64f98fa7
# define HASH_CONST_SHA224_H 0xbefa4fa4//0xbefa4fa4

/*
**	SHA384 Init register
*/
# define HASH_CONST_SHA384_A 0xcbbb9d5dc1059ed8//0xcbbb9d5dc1059ed8
# define HASH_CONST_SHA384_B 0x629a292a367cd507//0x629a292a367cd507
# define HASH_CONST_SHA384_C 0x9159015a3070dd17//0x9159015a3070dd17
# define HASH_CONST_SHA384_D 0x152fecd8f70e5939//0x152fecd8f70e5939
# define HASH_CONST_SHA384_E 0x67332667ffc00b31//0x67332667ffc00b31
# define HASH_CONST_SHA384_F 0x8eb44a8768581511//0x8eb44a8768581511
# define HASH_CONST_SHA384_G 0xdb0c2e0d64f98fa7//0xdb0c2e0d64f98fa7
# define HASH_CONST_SHA384_H 0x47b5481dbefa4fa4//0x47b5481dbefa4fa4

/*
**	SHA512 Init register
*/
# define HASH_CONST_SHA512_A 0x6a09e667f3bcc908//0x6a09e667f3bcc908
# define HASH_CONST_SHA512_B 0xbb67ae8584caa73b//0xbb67ae8584caa73b
# define HASH_CONST_SHA512_C 0x3c6ef372fe94f82b//0x3c6ef372fe94f82b
# define HASH_CONST_SHA512_D 0xa54ff53a5f1d36f1//0xa54ff53a5f1d36f1
# define HASH_CONST_SHA512_E 0x510e527fade682d1//0x510e527fade682d1
# define HASH_CONST_SHA512_F 0x9b05688c2b3e6c1f//0x9b05688c2b3e6c1f
# define HASH_CONST_SHA512_G 0x1f83d9abfb41bd6b//0x1f83d9abfb41bd6b
# define HASH_CONST_SHA512_H 0x5be0cd19137e2179//0x5be0cd19137e2179

typedef enum		e_sha_algo
{
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	NB_SHA,
}					t_sha_algo;

typedef enum		e_sha_func
{
	CH,
	MAJ,
	SUM0,
	SUM1,
	SIG0,
	SIG1,
}					t_sha_func;

typedef char	*(*t_sha_digest)(t_cmd_type cmd, unsigned char *entry, size_t entry_size, uint32_t flags);

typedef struct		s_sha
{
	t_cmd_type		cmd;
	char			padd[4];
	t_sha_digest	digest_func;
}					t_sha;

typedef enum	s_sha_register_32
{
	SHA_A,
	SHA_B,
	SHA_C,
	SHA_D,
	SHA_E,
	SHA_F,
	SHA_G,
	SHA_H,
	SHA_N_REGISTER,
}				t_sha_register_32;

typedef struct	s_sha_32
{
	uint32_t	hash[SHA_N_REGISTER];
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
}				t_sha_32;

typedef struct	s_sha_64
{
	uint64_t	hash[SHA_N_REGISTER];
	uint64_t	Wt[80];
	uint64_t	tmp1;
	uint64_t	tmp2;
	char		*input;
	size_t		entry_size_b;
	size_t		padding_size;
	size_t		zero_padding;
	size_t		block;
	uint32_t	flags;
	char		pad[4];
}				t_sha_64;

typedef union	s_sha_struct
{
	t_sha_32	sha32;
	t_sha_64	sha64;
}				t_sha_struct;

char			*sha_dispatcher(t_cmd_type cmd, unsigned char *entry, size_t entry_size, t_cmd_opt *opt);
void			sha32_verbose(t_sha_32 sha);
void			sha64_verbose(t_sha_64 sha);

char			*sha_32_digest(t_cmd_type cmd, unsigned char *entry, size_t entry_size, uint32_t flags);
uint32_t		sha_32_func_tri(t_sha_func func, uint32_t x, uint32_t y, uint32_t z);
uint32_t		sha_32_func_mono(t_sha_func func, uint32_t x);
void			sha_32_core(t_sha_32 *sha, uint32_t (*hash)[SHA_N_REGISTER]);

char			*sha_64_digest(t_cmd_type cmd, unsigned char *entry, size_t entry_size, uint32_t flags);
uint64_t		sha_64_func_tri(t_sha_func func, uint64_t x, uint64_t y, uint64_t z);
uint64_t		sha_64_func_mono(t_sha_func func, uint64_t x);
void			sha_64_core(t_sha_64 *sha, uint64_t (*hash)[SHA_N_REGISTER]);

#endif
