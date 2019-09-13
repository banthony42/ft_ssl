/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/09/13 17:38:31 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

/*
**	https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/
**	https://www.commentcamarche.net/contents/204-introduction-au-chiffrement-avec-des
**	Travmatth/ft_ssl give us more sources
**
**	DES algorithm steps :
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
**	Each round of encryption are made of 5 steps:
**	1 - key transformation
**	2 - expansion permutation
**	3 - s-box permutation
**	4 - p-box permutation
**	5 - XOR and swap
**
**
**
**
**
**
**
**
*/

int			usage_des(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [-a | -d | -e | -i [input_file] | -k [hexa_key] | -o [output_file] | -p [ascii_pwd] | -s [hexa_salt] | -v [init_vector]]");
	return (CMD_SUCCESS);
}

int			cmd_des(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	(void)cmd;
	(void)ac;
	(void)av;
	(void)opt;
	ft_putendl("Bijoul'");
	usage_des(av[0], "des");

	char *rd_passwd = getpass("enter decryption password:");

	if (rd_passwd == NULL)
		ft_putendl("NULL");
	else
		ft_putendl(rd_passwd);
	if (opt)
		ft_lstdel(&opt->flag_with_input, free_cmd_opt);

	return (CMD_SUCCESS);
}
