/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message_digest.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/18 18:40:34 by banthony          #+#    #+#             */
/*   Updated: 2019/07/19 12:48:02 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef MESSAGE_DIGEST_H
# define MESSAGE_DIGEST_H

# include "ft_ssl.h"

/*
**	MD5 options & MASK
*/

# define MD5_OPTS "-p;-q;-r;-s"
# define MD5_P_MASK 1
# define MD5_Q_MASK 1 << 1
# define MD5_R_MASK 1 << 2
# define MD5_S_MASK 1 << 3

# define MD5_OPT_ARG_VERBOSE_KEY "-verbose"
# define MD5_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define MD5_OPT_ARG_DUMP_KEY "-dump"
# define MD5_OPT_ARG_DUMP_VALUES "padding;block;all"

# define MD5_OARG_V_PAD 1
# define MD5_OARG_V_BLOCK 1 << 1
# define MD5_OARG_V_ALL 1 << 2

# define MD5_OARG_D_PAD 1 << 3
# define MD5_OARG_D_BLOCK 1 << 4
# define MD5_OARG_D_ALL 1 << 5

/*
**	SHA options & MASK
*/
# define SHA_OPTS "-p;-q;-r;-s"
# define SHA_P_MASK 1
# define SHA_Q_MASK 1 << 1
# define SHA_R_MASK 1 << 2
# define SHA_S_MASK 1 << 3

# define SHA_OPT_ARG_VERBOSE_KEY "-verbose"
# define SHA_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define SHA_OPT_ARG_DUMP_KEY "-dump"
# define SHA_OPT_ARG_DUMP_VALUES "padding;block;all"

# define SHA_OARG_V_PAD 1
# define SHA_OARG_V_BLOCK 1 << 1
# define SHA_OARG_V_ALL 1 << 2

# define SHA_OARG_D_PAD 1 << 3
# define SHA_OARG_D_BLOCK 1 << 4
# define SHA_OARG_D_ALL 1 << 5

/*
**	************************ MD5 ************************
*/

/*
**	Constantes d'initialisation pour le hash
*/

# define HASH_CONST_A 0x67452301
# define HASH_CONST_B 0xefcdab89
# define HASH_CONST_C 0x98badcfe
# define HASH_CONST_D 0x10325476

typedef enum		e_md5_register
{
	MD5_A,
	MD5_B,
	MD5_C,
	MD5_D,
	MD5_N_REGISTER,
}					t_md5_register;

typedef struct		s_md5
{
	uint32_t		hash[MD5_N_REGISTER];
	char			*input;
	size_t			entry_size_b;
	size_t			padding_size;
	size_t			zero_padding;
	size_t			block;
	uint32_t		flags;
	char			pad[4];
}					t_md5;

/*
**	Result of function - use to compute hash register
*/
typedef struct		s_md5_data
{
	uint32_t		f;
	uint32_t		i_w;
}					t_md5_data;

/*
**	MD5 function & hash
*/

uint32_t			md5_func_f(uint32_t b, uint32_t c, uint32_t d);
uint32_t			md5_func_g(uint32_t b, uint32_t c, uint32_t d);
uint32_t			md5_func_h(uint32_t b, uint32_t c, uint32_t d);
uint32_t			md5_func_i(uint32_t b, uint32_t c, uint32_t d);

char				*md5_digest(unsigned char *entry, size_t entry_size,
								uint32_t flags);
void				md5_verbose(t_md5 md5);
void				md5_compute(uint32_t (*word)[16],
								uint32_t (*hash_r)[MD5_N_REGISTER],
								t_md5_data data, int i);

/*
**	************************ SHA ************************
*/

/*
**	Les constantes d'initialisation se trouve dans sha_hash_32/64
*/

typedef enum		e_sha_algo
{
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	SHA_512_224,
	SHA_512_256,
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

typedef char		*(*t_sha_digest)(t_cmd_type cmd, unsigned char *entry,
									size_t entry_size, uint32_t flags);

typedef struct		s_sha
{
	t_cmd_type		cmd;
	char			padd[4];
	t_sha_digest	digest_func;
}					t_sha;

typedef enum		e_sha_register_32
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
}					t_sha_register_32;

typedef struct		s_sha_32
{
	uint32_t		hash[SHA_N_REGISTER];
	char			*input;
	size_t			entry_size_b;
	size_t			padding_size;
	size_t			zero_padding;
	size_t			block;
	uint32_t		flags;
	uint32_t		wt[64];
	uint32_t		tmp1;
	uint32_t		tmp2;
	char			pad[4];
}					t_sha_32;

typedef struct		s_sha_64
{
	uint64_t		hash[SHA_N_REGISTER];
	uint64_t		wt[80];
	uint64_t		tmp1;
	uint64_t		tmp2;
	char			*input;
	size_t			entry_size_b;
	size_t			padding_size;
	size_t			zero_padding;
	size_t			block;
	uint32_t		flags;
	char			pad[4];
}					t_sha_64;

char				*sha_dispatcher(t_cmd_type cmd, unsigned char *entry,
									size_t entry_size, t_cmd_opt *opt);
void				sha32_verbose(t_sha_32 sha);
void				sha64_verbose(t_sha_64 sha);

char				*sha_32_digest(t_cmd_type cmd, unsigned char *entry,
									size_t entry_size, uint32_t flags);
uint32_t			sha_32_func_tri(t_sha_func func, uint32_t x, uint32_t y,
									uint32_t z);
uint32_t			sha_32_func_mono(t_sha_func func, uint32_t x);
void				sha_32_core(t_sha_32 *sha,
								uint32_t (*hash)[SHA_N_REGISTER]);

char				*sha_64_digest(t_cmd_type cmd, unsigned char *entry,
									size_t entry_size, uint32_t flags);
uint64_t			sha_64_func_tri(t_sha_func func, uint64_t x, uint64_t y,
									uint64_t z);
uint64_t			sha_64_func_mono(t_sha_func func, uint64_t x);
void				sha_64_core(t_sha_64 *sha,
								uint64_t (*hash)[SHA_N_REGISTER]);

void				sha_512_224_last_hash(char (*footprint)[512 + 1],
											uint64_t hash);

#endif
