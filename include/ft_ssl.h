/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:02:57 by banthony          #+#    #+#             */
/*   Updated: 2019/02/10 19:52:21 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include "libft.h"
# include "utils.h"
# include <stdint.h>

/*
**	MD5 options & MASK
*/
# define MD5_OPTS "-p;-q;-r;-s"
# define MD5_P_MASK 1
# define MD5_Q_MASK 1 << 1
# define MD5_R_MASK 1 << 2
# define MD5_S_MASK 1 << 3

/*
**	SHA256 options & MASK
*/
# define SHA256_OPTS "-p;-q;-r;-s"
# define SHA256_P_MASK 1
# define SHA256_Q_MASK 1 << 1
# define SHA256_R_MASK 1 << 2
# define SHA256_S_MASK 1 << 3

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
	SHA256,
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
	uint32_t	opts_flag;
	uint32_t	opts_param_flag;
	int			end;
}				t_cmd_opt;

typedef int		(*t_cmd_usage)(char *cmd);
typedef int		(*t_cmd_func)(int ac, char **av, t_cmd_opt *opts);

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
**	Fonction ssl
*/

int				ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd);
int				ssl_cmd_parser(int ac, char **av, t_parsing_param param
									, t_cmd_opt *opt);

/*
**	Commandes
*/

int				cmd_md5(int ac, char **av, t_cmd_opt *opts);
int				cmd_sha256(int ac, char **av, t_cmd_opt *opts);
int				cmd_test(int ac, char **av, t_cmd_opt *opts);

int				usage_md5(char *exe);
int				usage_sha256(char *exe);
int				usage_test(char *exe);

#endif


















