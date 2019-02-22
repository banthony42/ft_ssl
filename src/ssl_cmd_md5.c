/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_md5.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/11 18:44:23 by banthony          #+#    #+#             */
/*   Updated: 2019/02/22 20:02:31 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			usage_md5(char *exe)
{
	ft_putstr(exe);
	ft_putendl(" md5 usage");
	return (CMD_SUCCESS);
}


static uint32_t function_f(uint32_t b, uint32_t c, uint32_t d)
{
	return ((b & c) | (~b & d));
}

static uint32_t function_g(uint32_t b, uint32_t c, uint32_t d)
{
	return ((b & d) | (c & ~d));
}

static uint32_t function_h(uint32_t b, uint32_t c, uint32_t d)
{
	return (b ^ c ^ d);
}

static uint32_t function_i(uint32_t b, uint32_t c, uint32_t d)
{
	return (c ^ (b | ~d));
}

static uint32_t	rotate_left(uint32_t value, uint32_t shift)
{
	return ((value << shift) | (value >> (32 - shift)));
}

static uint32_t swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

/*
**	Valeurs de decalage binaire
*/

static const uint32_t shifter[64] =
{
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

/*
** Lookup table, Partie entiere des sinus d'un int
*/

static const uint32_t sin_const[64] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static char	*md5_digest(char *entry)
{
	t_md5		md5;
	int			i;
	uint64_t	input_bits_size;

	ft_memset(&md5, 0, sizeof(md5));
	md5.input_size = ft_strlen(entry) * 8;
	// Initialisation des valeurs de hachage
	md5.hash[A] = HASH_CONST_A;
	md5.hash[B] = HASH_CONST_B;
	md5.hash[C] = HASH_CONST_C;
	md5.hash[D] = HASH_CONST_D;

	// Pre-processing: input_size start with entry size in bits + 1
	input_bits_size = md5.input_size + 1;

	// Increase input_size to reach a length up to 64 bits fewer than a multiple of 512. (448)
	// 64 bits fewer because in a next step, we will add the entry size coded on 64bits

	while ((input_bits_size % 512) != 448)
		input_bits_size++;
	md5.zero_padding = input_bits_size - md5.input_size - 1;
	printf("%spad:%llu - number of 0:%zu%s\n", SH_YELLOW, input_bits_size, md5.zero_padding, SH_WHITE);
	printf("%stotal:%llu - octet:%llu%s\n", SH_YELLOW, input_bits_size + 64,
		   (input_bits_size + 64) >> 3, SH_WHITE);

	// input_size = src_size_in bit + input_size_in_bit + 64bits (for src size)
	// then divide the result by 8 (>> 3), to get the size in byte.
	if (!(md5.input = (char*)ft_memalloc((input_bits_size + 64) >> 3)))
		return (NULL);

	// Mettre tout les bits a 0
	ft_memset(md5.input, 0, (input_bits_size + 64) >> 3);

	// Copie du message
	ft_memcpy(md5.input, entry, ft_strlen(entry));
	// Premier bit apres le message a 1
	md5.input[ft_strlen(entry)] = (char)128;

	// Encodage de la taille du message sur les 64 bits qui suivent en little-endian
	md5.input[(input_bits_size / 8)] = (char)((md5.input_size) & 0x00000000000000ffULL);
	md5.input[(input_bits_size / 8) + 1] = (char)(((md5.input_size) & 0x000000000000ff00ULL) >> 8);
	md5.input[(input_bits_size / 8) + 2] = (char)(((md5.input_size) & 0x0000000000ff0000ULL) >> 16);
	md5.input[(input_bits_size / 8) + 3] = (char)(((md5.input_size) & 0x00000000ff000000ULL) >> 24);
	md5.input[(input_bits_size / 8) + 4] = (char)(((md5.input_size) & 0x000000ff00000000ULL) >> 32);
	md5.input[(input_bits_size / 8) + 5] = (char)(((md5.input_size) & 0x0000ff0000000000ULL) >> 40);
	md5.input[(input_bits_size / 8) + 6] = (char)(((md5.input_size) & 0x00ff000000000000ULL) >> 48);
	md5.input[(input_bits_size / 8) + 7] = (char)(((md5.input_size) & 0xff00000000000000ULL) >> 56);

	ft_print_memory(md5.input, (input_bits_size + 64) >> 3);

	int bloc = -1;
	int max_bloc = (int)(input_bits_size + 64) / 512;	// Nombre de blocs de 512 bits dans input
	uint32_t word[16];	// 16 variables de 32bits = 512bits
	uint32_t hash_register[N_INDEX];
	uint32_t tmp;
	uint32_t i_w = 0;
	uint32_t f = 0;
	// Pour chaque bloc de 512 bits dans input
	while (++bloc < max_bloc)
	{
		i = -1;
		printf("%sbloc:%d%s\n", SH_RED, bloc, SH_WHITE);
		// Split du bloc actuel de 512bits en 16 variables de 32bits
		while (++i < 16)
		{
			ft_memcpy(&word[i], &md5.input[(bloc*64) + (i * 4)], sizeof(uint32_t));
			ft_print_memory(&word[i], sizeof(uint32_t));
		}

		// Init des registres de hachage
		hash_register[A] = md5.hash[A];
		hash_register[B] = md5.hash[B];
		hash_register[C] = md5.hash[C];
		hash_register[D] = md5.hash[D];

		i = -1;
		// Boucle principale
		while (++i < 64)
		{
			// ronde 1
 			if (0 <= i && i <= 15)
			{
				f = function_f(hash_register[B], hash_register[C], hash_register[D]);
				i_w = (uint32_t)i;
			}
			// ronde 2
			else if (16 <= i && i <= 31)
			{
				f = function_g(hash_register[B], hash_register[C], hash_register[D]);
				i_w = (5 * i + 1) % 16;
			}
			// ronde 3
			else if (32 <= i && i <= 47)
			{
				f = function_h(hash_register[B], hash_register[C], hash_register[D]);
				i_w = (3 * i + 5) % 16;
			}
			// ronde 4
			else if (48 <= i && i<= 63)
			{
				f = function_i(hash_register[B], hash_register[C], hash_register[D]);
				i_w = (7 * i) % 16;
			}
			// Modifications des registres
			tmp = hash_register[D];
			hash_register[D] = hash_register[C];
			hash_register[C] = hash_register[B];
			hash_register[B] = (rotate_left((hash_register[A] + f + sin_const[i] + word[i_w]), shifter[i]))
									+ hash_register[B];
			hash_register[A] = tmp;
		}
		// Ajout des registres au valeurs de hachage
		md5.hash[A] += hash_register[A];
		md5.hash[B] += hash_register[B];
		md5.hash[C] += hash_register[C];
		md5.hash[D] += hash_register[D];
	}
	char *footprint = NULL;
	char *hash_str = NULL;
	i = -1;
	int test;
	while (++i < N_INDEX)
	{
		test = (int)swap_uint32(md5.hash[i]);
		hash_str = ft_itoa_base(test, 16);
		ft_putendlcol(SH_GREEN, hash_str);
		printf("%s%08x%s\n", SH_RED, test, SH_WHITE);
		ft_strjoin_replace(&footprint, hash_str);
		ft_strdel(&hash_str);
	}
	return (NULL);
}

static void	md5_display_output(char *md5_result, char *entry,
								uint32_t opt, int is_str)
{
	if (opt & MD5_Q_MASK)
		ft_putendl(md5_result);
	else if (opt & MD5_R_MASK)
	{
		ft_putstr(md5_result);
		ft_putstr(" ");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putstr("\"\n");
		else
			ft_putchar('\n');
	}
	else
	{
		ft_putstr("MD5(");
		if (is_str)
			ft_putchar('"');
		ft_putstr(entry);
		if (is_str)
			ft_putchar('"');
		ft_putstr(")= ");
		ft_putendl(md5_result);
	}
}

static int	browse_argv(int ac, char **av, t_cmd_opt *opts, int i_str)
{
	int		i;
	int		fd;
	char	*md5_result;
	char	*entry;

	if (!opts)
		return (CMD_SUCCESS);
	i = opts->end - 1;
	entry = NULL;
	fd = 0;
	while (++i < ac)
	{
		if (i != i_str)
		{
			if (!(entry = read_file(av[i])))
				continue ;
			md5_result = md5_digest(entry);
			if (close(fd) < 0)
				return (CMD_ERROR);
		}
		else
			md5_result = md5_digest(av[i]);
		md5_display_output(md5_result, av[i], opts->opts_flag, !(i != i_str));
		ft_strdel(&md5_result);
		ft_strdel(&entry);
	}
	return (CMD_SUCCESS);
}

/*
**	No arg	- read from stdin
**	arg > 0	- open as a file.
**	-p		- echo STDIN on STDOUT and write result on STDOUT
**	-q		- quiet mode, dont print "MD5 (arg) = "
**	-r		- reverse output
**	-s		- use argv as string to use for the checksum
**			keep in memory the s index in argv
**			index_s + 1 use as string for checksum
**			index_s + n use as file, try to open it
*/

int			cmd_md5(int ac, char **av, t_cmd_opt *opts)
{
	char	*entry;
	char	*result;
	int		i_str;

	i_str = -2;
	entry = NULL;
	result = NULL;
	if (!opts || !opts->end || (opts && (opts->opts_flag & MD5_P_MASK)))
	{
		if (!(entry = read_cat(STDIN_FILENO)))
			return (CMD_ERROR);
		if (opts && opts->opts_flag & MD5_P_MASK)
			ft_putstr(entry);
		result = md5_digest(entry);
		if (!ft_strchr(entry, '\n'))
			ft_putchar('\n');
		ft_putendl(result);
		ft_strdel(&entry);
		ft_strdel(&result);
	}
	if (opts && (opts->opts_flag & MD5_S_MASK))
		i_str = find_key(av, ac, "-s");
	if (i_str < 0)
		i_str = -2;
	if (opts && opts->end)
		browse_argv(ac, av, opts, i_str + 1);
	return (CMD_SUCCESS);
}
