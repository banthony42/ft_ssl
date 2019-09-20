/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/09/20 11:46:33 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

/*
**	https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/
**	https://www.commentcamarche.net/contents/204-introduction-au-chiffrement-avec-des
**	Travmatth/ft_ssl give us more sources
**
**	DES ALGORITHM STEPS:
**
**	The algorithm works on block of 64 bits (8 octets):
**
**	1 - initial_permutation(plain_text_block)
**	2 - split block permuted into two 32bits blocks. (left block LPT & right block RPT)
**	3 - RPT & LPT will be encrypt through 16 rounds of encryption
**	4 - final_permutation(joined_block(LPT, RPT))
**	5 - Result: 64 bits of cipher text, redo foreach 8 octets
**
**	initial_permutation(block_of_64bits) :
**	Replace the first 	bit ot the block by the 58th.
**	Replace the second	bit of the block by the 50th.
**	Replace the third	bit of the block by the 42th.
**	Replace the   n		bit of the block by the 58th - (8 * (n - 1))
**	... foreach bits
**
**	Results: (Numbers are the index of a bit in the 64bits block)
**	LPT:
**	octet 1 :	58 50 42 34 26 18 10 2
**	octet 2 :	60 52 44 36 28 20 12 4
**	octet 3 :	62 54 46 38 30 22 16 6
**	octet 4 :	64 56 48 40 32 24 16 8
**
**	RPT:
**	octet 5 :	57 49 41 33 25 17  9 1
**  octet 6 :	59 51 43 35 27 19 11 3
**	octet 7 :	61 33 45 37 29 11 13 5
**	octet 8 :	63 55 47 39 31 23 15 7
**
**	ROUND OF ENCRYPTION STEPS:
**	1 - key transformation
**	2 - expansion permutation
**	3 - s-box permutation
**	4 - p-box permutation
**	5 - XOR and swap
**
**	PASSWORD, KEY, SALT & INIT VECTOR:
**	If the key is absent (-k) we need to create one:
**
**	1 - So if password (-p) is missing, ask the user.
**	2 - If the salt is missing (-s), use /dev/random to create one.
**	3 - Create the key using 8 first bytes of md5(password + salt)
**	4 - If iv is missing (-v), create it using 8 last bytes if md5(password + salt)
**
*/

static void des_cipher(t_des des, t_cmd_type cmd, char *entry)
{
	(void)des;
	ft_putstrcol("\nENTRY:", SH_RED);
	ft_putendl(entry);
}

int			usage_des(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-a | -d | -e | -i [input_file] | -k [hexa_key] | -o [output_file] |"
				 "\n\t-p [ascii_pwd] | -s [hexa_salt] | -v [init_vector]]");
	return (CMD_SUCCESS);
}

static t_bool		parse_input(t_list *elem, void *data)
{
	t_opt_arg	*flag;
	t_des		*des;

	if (!elem || !data)
		return (false);
	des = (t_des*)data;
	flag = (t_opt_arg*)elem->content;
	if (!flag->key || !flag->values)
		return (false);
	if (!ft_strcmp(flag->key, CIPHER_INPUT_FILE_KEY))
		des->in = open_file(flag->values, O_RDONLY, "No such file or directory");
	else if (!ft_strcmp(flag->key, CIPHER_OUTPUT_FILE_KEY))
		des->out = open_file(flag->values, O_CREAT | O_EXCL | O_RDWR, "File already exist");
	else if (!ft_strcmp(flag->key, DES_HEXAKEY_KEY))
		des->hexa_key = flag->values;
	else if (!ft_strcmp(flag->key, DES_PASS_KEY))
		des->passwd = flag->values;
	else if (!ft_strcmp(flag->key, DES_SALT_KEY))
		ft_strncpy(des->salt, flag->values, SALT_LENGTH);
	else if (!ft_strcmp(flag->key, DES_INIT_VECTOR_KEY))
		des->i_vector = flag->values;
	if (des->in < 0 || des->out < 0)
		return false;
	return true;
}

static t_bool	ft_ishexa(char *str)
{
	int i;

	i = 0;
	if (!str || ft_strlen(str) == 0)
		return (false);
	while(str[i])
	{
		if (!ft_isdigit(str[i]))
			if (ft_toupper(str[i]) < 'A' || ft_toupper(str[i]) > 'F')
				return (false);
		i++;
	}
	return (true);
}

static t_bool	create_salt(t_des *des)
{
	int		fd;
	int		index;
	char	buffer[2];
	char	generated_salt[SALT_LENGTH];

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
		return (false);
	index = 0;
	ft_memset(generated_salt, 0, SALT_LENGTH);
	buffer[1] = '\0';
	while(read(fd, buffer, 1))
	{
		if (ft_ishexa(buffer))
			generated_salt[index++] = buffer[0];
		if (index >= SALT_LENGTH)
			break;
	}
	ft_strncpy(des->salt, generated_salt, SALT_LENGTH);
	return (true);
}

static t_bool	create_key(t_des *des)
{
	char	*result;
	char	*entry;
	size_t	entry_len;

	entry_len = ft_strlen(des->passwd) + ft_strlen(des->salt) + 1;
	entry = ft_strnew(entry_len);
	ft_memset(entry, 0, entry_len);
	ft_strncpy(entry, des->passwd, ft_strlen(des->passwd));
	ft_strcat(entry, des->salt);
	if (!(result = md5_digest((unsigned char*)entry, ft_strlen(entry), 0)) ||
		ft_strlen(result) != 32)
	{
		ft_putendl("An error occured during the creation of the key.");
		ft_strdel(&entry);
		return (false);
	}
	des->hexa_key = ft_strsub(result, 0, 8);
	ft_print_memory(result, 32);
	if (!des->i_vector)
		des->i_vector = ft_strsub(result, 24, 32);
	ft_putstr("\nsalt =\t");
	ft_putendl(des->salt);
	ft_putstr("key =\t");
	ft_putendl(des->hexa_key);
	ft_putstr("iv =\t");
	ft_putendl(des->i_vector);
	ft_strdel(&entry);
	return (true);
}

// Use getpassphrase instead. (getpass not secure)
static t_bool	get_pass(t_des *des)
{
	char	user_passwd[_PASSWORD_LEN];
	char	check_passwd[_PASSWORD_LEN];

	if (!des->passwd)
	{
		ft_memset(user_passwd, 0, _PASSWORD_LEN);
		ft_memset(check_passwd, 0, _PASSWORD_LEN);
		ft_strncpy(user_passwd, getpass("Enter decryption password:"), _PASSWORD_LEN);
		ft_strncpy(check_passwd, getpass("Verifying - Enter decryption password:"), _PASSWORD_LEN);
		if (ft_strcmp(user_passwd, check_passwd))
		{
			ft_putendl("Verify failure\nbad password read");
			return (false);
		}
		des->passwd = ft_strdup(user_passwd);
	}
	if (!ft_strlen(des->salt))
		create_salt(des);
	create_key(des);
	return (true);
}

static int			des_end(t_des des, t_cmd_opt *opt, int error, char *mess)
{
	if (mess)
		ft_putendl(mess);
	if (opt)
		ft_lstdel(&opt->flag_with_input, free_cmd_opt);
	if (des.in != STDIN_FILENO && des.in > 0)
		ft_close(des.in);
	if (des.out != STDOUT_FILENO && des.out > 0)
		ft_close(des.out);
	return (error);
}

int			cmd_des(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	t_des	des;
	size_t	size;
	char	*entry;

	(void)ac;
	entry = NULL;
	ft_memset(&des, 0, sizeof(des));
	des.out = STDOUT_FILENO;
	if (opt && opt->opts_flag & CIPHER_DECODE_MASK)
		des.cipher_mode = CIPHER_DECODE;
	if (opt && opt->opts_flag & DES_B64_MASK)
		des.use_b64 = true;
	if (opt && opt->flag_with_input)
		ft_lstiter_while_true(opt->flag_with_input, &des, parse_input);
	if (des.in < 0 || des.out < 0)
		return des_end(des, opt, CMD_ERROR, NULL);
	if (!des.hexa_key && !get_pass(&des))
		return (CMD_ERROR);
	if (!opt || !opt->end)
	{
		if (!(entry = (char*)read_cat(des.in, &size)))
			return des_end(des, opt, CMD_ERROR, "Can't read input.");
		des_cipher(des, entry);
		ft_strdel(&entry);
		return des_end(des, opt, CMD_SUCCESS, NULL);
	}
	des_cipher(des, av[opt->end]);
	return des_end(des, opt, CMD_SUCCESS, NULL);
}
