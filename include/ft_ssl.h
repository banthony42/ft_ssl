/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:02:57 by banthony          #+#    #+#             */
/*   Updated: 2019/03/10 19:11:35 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include "libft.h"
# include "utils.h"
# include <math.h>
# include <stdlib.h>
# include <stdint.h>
# include <unistd.h>
# include <fcntl.h>

#include <stdio.h>

# define MAXBYTE 3754996

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
**	SHA224 options & MASK
*/
# define SHA224_OPTS "-p;-q;-r;-s"
# define SHA224_P_MASK 1
# define SHA224_Q_MASK 1 << 1
# define SHA224_R_MASK 1 << 2
# define SHA224_S_MASK 1 << 3

# define SHA224_OPT_ARG_VERBOSE_KEY "-verbose"
# define SHA224_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define SHA224_OPT_ARG_DUMP_KEY "-dump"
# define SHA224_OPT_ARG_DUMP_VALUES "padding;block;all"

# define SHA224_OARG_V_PAD 1
# define SHA224_OARG_V_BLOCK 1 << 1
# define SHA224_OARG_V_ALL 1 << 2

# define SHA224_OARG_D_PAD 1 << 3
# define SHA224_OARG_D_BLOCK 1 << 4
# define SHA224_OARG_D_ALL 1 << 5

/*
**	SHA256 options & MASK
*/
# define SHA256_OPTS "-p;-q;-r;-s"
# define SHA256_P_MASK 1
# define SHA256_Q_MASK 1 << 1
# define SHA256_R_MASK 1 << 2
# define SHA256_S_MASK 1 << 3

# define SHA256_OPT_ARG_VERBOSE_KEY "-verbose"
# define SHA256_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define SHA256_OPT_ARG_DUMP_KEY "-dump"
# define SHA256_OPT_ARG_DUMP_VALUES "padding;block;all"

# define SHA256_OARG_V_PAD 1
# define SHA256_OARG_V_BLOCK 1 << 1
# define SHA256_OARG_V_ALL 1 << 2

# define SHA256_OARG_D_PAD 1 << 3
# define SHA256_OARG_D_BLOCK 1 << 4
# define SHA256_OARG_D_ALL 1 << 5

/*
**	SHA384 options & MASK
*/
# define SHA384_OPTS "-p;-q;-r;-s"
# define SHA384_P_MASK 1
# define SHA384_Q_MASK 1 << 1
# define SHA384_R_MASK 1 << 2
# define SHA384_S_MASK 1 << 3

# define SHA384_OPT_ARG_VERBOSE_KEY "-verbose"
# define SHA384_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define SHA384_OPT_ARG_DUMP_KEY "-dump"
# define SHA384_OPT_ARG_DUMP_VALUES "padding;block;all"

# define SHA384_OARG_V_PAD 1
# define SHA384_OARG_V_BLOCK 1 << 1
# define SHA384_OARG_V_ALL 1 << 2

# define SHA384_OARG_D_PAD 1 << 3
# define SHA384_OARG_D_BLOCK 1 << 4
# define SHA384_OARG_D_ALL 1 << 5

/*
**	SHA512 options & MASK
*/
# define SHA512_OPTS "-p;-q;-r;-s"
# define SHA512_P_MASK 1
# define SHA512_Q_MASK 1 << 1
# define SHA512_R_MASK 1 << 2
# define SHA512_S_MASK 1 << 3

# define SHA512_OPT_ARG_VERBOSE_KEY "-verbose"
# define SHA512_OPT_ARG_VERBOSE_VALUES "padding;block;all"
# define SHA512_OPT_ARG_DUMP_KEY "-dump"
# define SHA512_OPT_ARG_DUMP_VALUES "padding;block;all"

# define SHA512_OARG_V_PAD 1
# define SHA512_OARG_V_BLOCK 1 << 1
# define SHA512_OARG_V_ALL 1 << 2

# define SHA512_OARG_D_PAD 1 << 3
# define SHA512_OARG_D_BLOCK 1 << 4
# define SHA512_OARG_D_ALL 1 << 5

/*
**	test options & MASK
**	Options simples -[OptionName]
*/

# define TEST_OPTS "-p;-q;-r;-s;-help"
# define TEST_P_MASK 1
# define TEST_Q_MASK 1 << 1
# define TEST_R_MASK 1 << 2
# define TEST_S_MASK 1 << 3
# define TEST_HELP_MASK 1 << 4

/*
**	Options parametrable -[OptionName] [parametre]
**	Definir l'option (ex:-print) puis les valeurs possible pour le parametre
**	(ex:red;green;blue) Les valeurs doivent etre separe par un ;
*/
# define TEST_OPT_PRINT_KEY "-print"
# define TEST_OPT_PRINT_VALUES "red;green;blue"
# define TEST_OPT_ARG_KEY "-arg"
# define TEST_OPT_ARG_VALUES "value1;value2;valueX"
# define TEST_PRINT_RED_MASK 1
# define TEST_PRINT_GREEN_MASK 1 << 1
# define TEST_PRINT_BLUE_MASK 1 << 2
# define TEST_ARG_VALUE1_MASK 1 << 3
# define TEST_ARG_VALUE2_MASK 1 << 4
# define TEST_ARG_VALUEX_MASK 1 << 5

/*
**	Definit le status d'une commande, ou du parseur.
**
**	PARSING_SUCCESS = tout va bien
**	PARSING_FAILURE = erreur grave, malloc, etc, ...
**	PARSING_NOTAN_OPT = le parseur s'est arrete, l'argument n'est pas une option
**	PARSING_OPT_ERROR = Erreur l'options est invalide
*/
typedef enum	e_cmd_status
{
	CMD_SUCCESS = 0,
	CMD_MISMATCH = -1,
	CMD_USAGE = -2,
	CMD_ERROR = -3,
	PARSING_SUCCESS = -10,
	PARSING_FAILURE = -11,
	PARSING_NOTAN_OPT = -12,
	PARSING_OPT_ERROR = -13,
}				t_cmd_status;

/*
**	MD5		- ./ft_ssl md5		- cryptage md5
**	SHA256	- ./ft_ssl sha256	- cryptage sha256
**	TEST	- ./ft_ssl test		- test du parseur
*/
typedef enum	e_cmd_type
{
	MD5,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	TEST,
	NB_CMD,
}				t_cmd_type;

/*
**	Definit une option parametrable, (ex:./ft_ssl cmd -[OptionName] [parametre])
**	Les champs key et value sont rempli a la compilation avec une grammaire.
**	Les grammaire sont definit plus haut.
**	(ex:TEST_OPT_PRINT_KEY & TEST_OPT_PRINT_VALUES)
*/
typedef struct	s_opt_arg
{
	char		*key;
	char		*values;
}				t_opt_arg;

/*
**	Definit les parametre de parsing
**	cmd = commande pour laquelle les parametres s'applique
**	opts_with_arg = definit si la commande prend des options parametrable
**	opts = options simple de la commande, separe par des ;
**	opts_len = taille de opts
**	opts_arg = options parametrable (ex: -print blue) voir formats plus haut
*/

# define MAX_OPTS_ARG 8

typedef struct	s_parsing_param
{
	t_cmd_type	cmd;
	t_bool		opts_with_arg;
	char		*opts;
	size_t		opts_len;
	t_opt_arg	opts_arg[MAX_OPTS_ARG];
	size_t		opts_arg_len;
}				t_parsing_param;

/*
**	Definit les informations recupere par le parseur.
**	opts_flag = flags options simples, 1 bit = une option - a lire avec les mask
**	opts_param_flag = Idem mais pour les options parametrable
**	end = Index ou le parseur s'est arrete
*/
typedef struct	s_cmd_opt
{
	t_cmd_type	cmd;	// update comment
	uint32_t	opts_flag;
	uint32_t	opts_pflag;
	int			end;
}				t_cmd_opt;

typedef int		(*t_cmd_usage)(char *exe, char *cmd_name);
typedef int		(*t_cmd_func)(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);

/*
**	Definit une commande:
**	name = nom de la commande
**	len = taille du nom de la commande
**	func = fonction qui execute la commande
**	usage = fonction decrivant le fonctionnement de la commande
*/

typedef struct	s_cmd
{
	char		*name;
	size_t		len;
	t_cmd_func	func;
	t_cmd_usage	usage;
}				t_cmd;


/*
**	General
*/

char			*itoa_base_uint32(uint32_t value, int base);
char			*itoa_base_uint64(uint64_t value, int base);
unsigned char	*read_cat(int fd, size_t *size);
unsigned char	*read_file(char *path, size_t *size);
int				find_key(char **av, int ac, char *key);
void			encode64_lendian(size_t size, char *octet);
void			encode64_bendian(size_t size, char *octet);
void			encode128_bendian(uint128_t size, char *octet);
uint32_t		swap_uint32(uint32_t val);
uint64_t		swap_uint64(uint64_t val);
uint32_t		rotate_left(uint32_t value, uint32_t shift);
uint32_t		rotate_right(uint32_t value, uint32_t shift);
uint64_t		rotate_r_64(uint64_t value, uint64_t shift);

/*
**	Fonction ssl
*/

char			*ssl_get_cmd_name(t_cmd_type cmd, t_bool toupper);
int				ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd);
int				ssl_cmd_parser(int ac, char **av, t_parsing_param param
									, t_cmd_opt *opt);

/*
**	Commandes
*/

int				cmd_md5(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_sha(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt);
int				cmd_sha384(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_sha512(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_test(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);

int				usage_md5(char *exe, char *cmd_name);
int				usage_sha(char *exe, char *cmd_name);
int				usage_sha384(char *exe, char *cmd_name);
int				usage_sha512(char *exe, char *cmd_name);
int				usage_test(char *exe, char *cmd_name);

#endif















