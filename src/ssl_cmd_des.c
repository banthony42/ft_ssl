/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/10/22 19:22:43 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

/*
**	DES ALGORITHM STEPS:
**
**	The algorithm works on block of 64 bits (8 octets):
**
**	1 - initial_permutation(plain_text_block)
**	2 - split block permuted into two 32bits blocks.
**		(left block LPT & right block RPT)
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
**	4 - If iv is missing (-v), create it using 8 last bytes of:
**		md5(password + salt)
*/

static const uint8_t	g_keyp[56] =
{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

static void		des_cipher(t_des des, t_cmd_type cmd, char *entry, size_t size)
{
	uint64_t	subkey[16];
	uint64_t	key;
	t_base64	b64;

	ft_memset(&b64, 0, sizeof(b64));
	b64.out = -1;
	b64.in = des.in;
	b64.cipher_mode = des.cipher_mode;
	hexastring_to_uint64(des.hexa_key, &key);
	key = bits_permutation(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);
	if (cmd == DES_ECB && des.cipher_mode == CIPHER_ENCODE)
	{
		des_ecb_encode(&des, entry, size, subkey);
		if (des.use_b64) {
			b64.out = des.out;
			base64_cipher(&b64, (char*)des.result, des.result_len);
		}
		else
			write(des.out, des.result, des.result_len);
	}
	else if (cmd == DES_CBC && des.cipher_mode == CIPHER_ENCODE)
		des_cbc_encode(&des, entry, size, subkey);
	else if (cmd == DES_ECB && des.cipher_mode == CIPHER_DECODE)
	{
		if (des.use_b64) {
			base64_cipher(&b64, entry, size);
			des_ecb_decode(&des, b64.result, b64.result_len, subkey);
			write(des.out, des.result, des.result_len);
		}
		else {
			des_ecb_decode(&des, entry, size, subkey);
			write(des.out, des.result, des.result_len);
		}
	}
	else if (cmd == DES_CBC && des.cipher_mode == CIPHER_DECODE)
		des_cbc_decode(&des, entry, size, subkey);
}

int				usage_des(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-a | -d | -e \n\t| -i [input_file]\n\t| -k [hexa_key]"
				"\n\t| -o [output_file]\n\t| -p [ascii_pwd]"
				"\n\t| -s [hexa_salt]\n\t| -v [init_vector]]");
	return (CMD_SUCCESS);
}

static t_bool	parse_input(t_list *elem, void *data)
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
		des->in = open_file(flag->values, O_RDONLY, NO_FILE_DIR);
	else if (!ft_strcmp(flag->key, CIPHER_OUTPUT_FILE_KEY))
		des->out = open_file(flag->values, O_CREAT | O_EXCL | O_RDWR, EXIST);
	else if (!ft_strcmp(flag->key, DES_HEXAKEY_KEY))
		des->hexa_key = flag->values;
	else if (!ft_strcmp(flag->key, DES_PASS_KEY))
		des->passwd = flag->values;
	else if (!ft_strcmp(flag->key, DES_SALT_KEY))
		ft_strncpy(des->salt, flag->values, SALT_LENGTH);
	else if (!ft_strcmp(flag->key, DES_INIT_VECTOR_KEY))
		des->i_vector = flag->values;
	if (des->in < 0 || des->out < 0)
		return (false);
	return (true);
}

static int		des_end(t_des des, t_cmd_opt *opt, int error, char *mess)
{
	if (mess)
		ft_putendl(mess);
	if (opt)
		ft_lstdel(&opt->flag_with_input, free_cmd_opt);
	if (des.in != STDIN_FILENO && des.in > 0)
		ft_close(des.in);
	if (des.out != STDOUT_FILENO && des.out > 0)
		ft_close(des.out);
	if (des.passwd != NULL)
		ft_strdel(&des.passwd);
	return (error);
}

int				cmd_des(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
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
		return (des_end(des, opt, CMD_ERROR, NULL));
	if (!des.hexa_key && !get_pass(&des))
		return (CMD_ERROR);
	if (!opt || !opt->end)
	{
		if (!(entry = (char*)read_cat(des.in, &size)))
			return (des_end(des, opt, CMD_ERROR, "Can't read input."));
		des_cipher(des, cmd, entry, size);
		ft_strdel(&entry);
		return (des_end(des, opt, CMD_SUCCESS, NULL));
	}
	des_cipher(des, cmd, av[opt->end], 0);
	return (des_end(des, opt, CMD_SUCCESS, NULL));
}
