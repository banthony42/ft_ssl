/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:02:57 by banthony          #+#    #+#             */
/*   Updated: 2019/02/08 17:39:37 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

#include "libft.h"
#include "utils.h"
#include <stdint.h>

# define MD5_OPTS "p;q;r;s"

# define SHA256_OPTS "p;q;r;s"

# define TEST_OPTS "p;q;r;s;help"
# define TEST_ARG_PRINT "print:red;blue;green"
# define TEST_ARG_X "arg:value1;value2;valueX"

typedef enum	e_cmd_status
{
	CMD_MISMATCH = -1,
	CMD_SUCCESS = 0,
	CMD_USAGE = 1,
	CMD_PARSING_SUCCESS = 2,
	CMD_PARSING_FAILURE = 3,
}				t_cmd_status;

typedef enum	e_cmd_type
{
	MD5,
	SHA256,
	TEST,
	NB_CMD,
}				t_cmd_type;

/*
**	Definit les parametre de parsing
**	cmd = commande pour laquelle les parametres s'applique
**	opts_with_arg = definit si la commande prend des options parametrable
**	opts = options simple de la commande, separe par des ;
**	opts_len = taille de opts
**	opts_arg = options parametrable (ex: -print blue) voir formats plus haut
**	can_read_stdin = true: la commande lit l'entree standard si aucune opts
**					false: la commande affiche son usage si aucune opts
*/

# define MAX_OPTS 16
# define MAX_OPTS_ARG 8

typedef struct	s_opt_arg
{
	char		*str;
	size_t		len;
}				t_opt_arg;

typedef struct	s_parsing_param
{
	t_cmd_type	cmd;
	t_bool		opts_with_arg;
	char		*opts;
	size_t		opts_len;
	t_opt_arg	opts_arg[MAX_OPTS_ARG];
	size_t		opts_arg_len;
}				t_parsing_param;

typedef struct	s_cmd_opt
{
	uint32_t	opts_flag;
	char		padding[4];
	t_opt_arg	opts_arg[MAX_OPTS_ARG];
	size_t		opts_arg_len;
}				t_cmd_opt;

/*
**	Definit une commande:
**	name = nom de la commande
**	len = taille du nom de la commande
**	func = fonction qui execute la commande
*/

typedef int			(*t_cmd_usage)(void);
typedef int			(*t_cmd_func)(int ac, char **av, t_cmd_opt *opts);

typedef struct	s_cmd
{
	char			*name;
	size_t			len;
	t_cmd_func		func;
	t_cmd_usage		usage;
}				t_cmd;

/*
**	Fonction ssl
*/
int			ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd);
int	ssl_cmd_parser(int ac, char **av, t_parsing_param param, t_cmd_opt *opt);

/*
**	Commandes
*/
int			cmd_md5(int ac, char **av, t_cmd_opt *opts);
int			cmd_sha256(int ac, char **av, t_cmd_opt *opts);
int			cmd_test(int ac, char **av, t_cmd_opt *opts);

int		usage_md5(void);
int		usage_sha256(void);
int		usage_test(void);

#endif










