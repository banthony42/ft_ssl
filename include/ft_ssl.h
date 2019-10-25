/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/08 13:02:57 by banthony          #+#    #+#             */
/*   Updated: 2019/10/25 15:07:50 by banthony         ###   ########.fr       */
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
# include "ft_ssl_man.h"

# define NO_FILE_DIR "No such file or directory"
# define EXIST "File already exist"

/*
**	Nombre de bit maximum a lire avec read
*/
# define MAXBYTE 8192

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
**	Important si vous utiliser le meme nom qu'une option simple qui
**	existe deja, l'option parametrable du meme nom sera ignoree.
**
**	Options parametrable -[OptionName] [parametre]
**	Definir l'option (ex:-print) puis les valeurs possible pour le parametre
**	(ex:red;green;blue) Les valeurs doivent etre separe par un ;
**
**	Il est aussi possible de prendre une entree utilisateur:
**	-[OptionName] [StringFromUser]
**	Pour cela il suffit d'utiliser OPT_FROM_USER
**	dans le champ value des parametres de parsing.
*/

# define OPT_FROM_USER "??"

# define TEST_OPT_STR_KEY "-string"
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
	PARSING_CONTINUE = -9,
	PARSING_SUCCESS = -10,
	PARSING_FAILURE = -11,
	PARSING_NOTAN_OPT = -12,
	PARSING_OPT_ERROR = -13,
}				t_cmd_status;

/*
**	MD5		- ./ft_ssl md5		- hashage md5
**	SHA256	- ./ft_ssl sha256	- hashage sha256
**	SHAXXX	- ./ft_ssl shaXXX	- hashage shaXXX
**	BASE64	- ./ft_ssl base64	- cryptage base64
**	MAN		- ./ft_ssl man [cmd]- Show man for cmd
**	TEST	- ./ft_ssl test		- test du parseur
*/
typedef enum	e_cmd_type
{
	MD5,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	SHA512_224,
	SHA512_256,
	BASE64,
	BASE64_URL,
	DES,
	DES_ECB,
	DES_CBC,
	DES_OFB,
	DES_CFB,
	MAN,
	TEST,
	NB_CMD,
}				t_cmd_type;

/*
**	Definit une option parametrable, (ex:./ft_ssl cmd -[OptionName] [parametre])
**	Les champs key et value sont rempli a la compilation avec une grammaire.
**	Les grammaire sont definit plus haut.
**	(ex:TEST_OPT_PRINT_KEY & TEST_OPT_PRINT_VALUES)
**
**	Aussi utilise pour les entree utilisateurs.
**	(Voir struct: t_cmd_opt, champ: str_from_user)
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
**	cmd = Le type de la commande
**	opts_flag = flags options simples, 1 bit = une option - a lire avec les mask
**	opts_param_flag = Idem mais pour les options parametrable
**	end = Index ou le parseur s'est arrete
*/
typedef struct	s_cmd_opt
{
	t_cmd_type	cmd;
	uint32_t	opts_flag;
	uint32_t	opts_pflag;
	int			end;
	t_list		*flag_with_input;
}				t_cmd_opt;

typedef int		(*t_cmd_usage)(char *exe, char *cmd_name);
typedef int		(*t_cmd_func)(int ac, char **av, t_cmd_type cmd
								, t_cmd_opt *opts);

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

typedef t_bool	(*t_list_condition)(t_list *elem, void *data);

/*
**	General
*/

unsigned char	*read_cat(int fd, size_t *size);
unsigned char	*read_file(char *path, size_t *size);
int				find_key(char **av, int ac, char *key);
int				open_file(const char *file, int flags, char *error);
void			ft_lstiter_while_true(t_list *lst, void *data,
										t_list_condition condition);
void			free_cmd_opt(void *opt, size_t opt_size);
void			encode64_lendian(size_t size, char *octet);
void			encode64_bendian(size_t size, char *octet);
void			encode128_bendian(size_t size, char *octet);
uint32_t		swap_uint32(uint32_t val);
uint64_t		swap_uint64(uint64_t val);
uint32_t		rotate_left(uint32_t value, uint32_t shift);
uint32_t		rotate_right(uint32_t value, uint32_t shift);
uint64_t		rotate_r_64(uint64_t value, uint64_t shift);
size_t			ft_strchrcount(const char *src, int c);

/*
**	Fonction ssl
*/

char			*ssl_get_cmd_name(t_cmd_type cmd, t_bool toupper);
int				ssl_cmd_dispatcher(int ac, char **av, t_cmd_type cmd);
int				ssl_cmd_parser(int ac, char **av, t_parsing_param param,
								t_cmd_opt *opt);
int				ssl_find_key_value(char *entry, char **values,
								t_opt_arg opt_arg, t_cmd_opt *opt);

/*
**	Commandes
*/

int				cmd_md5(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_sha(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt);
int				cmd_sha384(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_sha512(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_base64(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_des(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_man(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);
int				cmd_test(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opts);

int				usage_md5(char *exe, char *cmd_name);
int				usage_sha(char *exe, char *cmd_name);
int				usage_sha384(char *exe, char *cmd_name);
int				usage_sha512(char *exe, char *cmd_name);
int				usage_base64(char *exe, char *cmd_name);
int				usage_des(char *exe, char *cmd_name);
int				usage_man(char *exe, char *cmd_name);
int				usage_test(char *exe, char *cmd_name);

#endif
