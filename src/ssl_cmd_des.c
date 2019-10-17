/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/10/17 13:31:46 by banthony         ###   ########.fr       */
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

static const uint8_t g_keyp[56]=
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

//Initial Permutation Table
static const uint8_t initial_perm[64]=
{
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7
};

//Expansion D-box Table
static const uint8_t expansion[48]=
{
	32,1,2,3,4,5,4,5,
	6,7,8,9,8,9,10,11,
	12,13,12,13,14,15,16,17,
	16,17,18,19,20,21,20,21,
	22,23,24,25,24,25,26,27,
	28,29,28,29,30,31,32,1
};

// End of round permutation
static const uint8_t per[32]=
{    16,7,20,21,
		29,12,28,17,
		1,15,23,26,
		5,18,31,10,
		2,8,24,14,
		32,27,3,9,
		19,13,30,6,
		22,11,4,25
};

//Final Permutation Table
static const uint8_t final_perm[64]=
{    40,8,48,16,56,24,64,32,
		 39,7,47,15,55,23,63,31,
		 38,6,46,14,54,22,62,30,
		 37,5,45,13,53,21,61,29,
		 36,4,44,12,52,20,60,28,
		 35,3,43,11,51,19,59,27,
		 34,2,42,10,50,18,58,26,
		 33,1,41,9,49,17,57,25
};

uint64_t permute(uint64_t data, const uint8_t *matrix, size_t size)
{
	size_t   i;
	uint64_t permuted_data;

	i = 0;
	permuted_data = 0;
	while (i < size)
	{
		if (((data << (matrix[i] - 1)) & FIRST_BIT_64) != 0)
			permuted_data += (FIRST_BIT_64 >> i);
		i++;
	}
	return (permuted_data);
}

static void encryption_round(uint32_t *l_block, uint32_t *r_block, uint64_t subkey[16])
{
	int			i;
	uint64_t	xored_data;
	uint32_t	sbox_result;

	i = -1;
	while (++i < 16)
	{
//		ft_putendl("========= SLICE ==========");
//		ft_print_memory(l_block, sizeof(uint32_t));
//		ft_print_memory(r_block, sizeof(uint32_t));

		// Right block Expansion to 48 bits
//		ft_putendlcol(SH_YELLOW, "RIGHT BLOCK EXPANSION");
		uint64_t right = *r_block;
		uint64_t exp = permute(right << 32, expansion, 48);
		exp = exp >> 16;
//		ft_putendlcol(SH_GREEN, "=========RIGHT PERMUTE==========");
//		ft_print_memory(&exp, sizeof(uint64_t));

		// XOR the result with the sub key corresponding to this round number
		xored_data = exp ^ (subkey[i] >> 16);
		// S Box
		apply_sbox(xored_data, &sbox_result);
		// Permutation
		uint64_t t = sbox_result;
		t = t << 32;
		sbox_result = permute(t, per, 32) >> 32;
		// Final xor
		sbox_result ^= *l_block;

		*l_block = *r_block;
		*r_block = sbox_result;
	}
}

static void decryption_round(uint32_t *l_block, uint32_t *r_block, uint64_t subkey[16])
{
	int i;
	uint64_t exp;
	uint64_t xored_data;
	uint32_t tmp_left;
	uint64_t right = *r_block;
	uint32_t	sbox_result;

	i = 15;
	while (i >= 0)
	{
		right = *r_block;
		exp = permute(right << 32, expansion, 48);
		exp = exp >> 16;
        //ft_putendl("=== exp ===");
		//ft_print_memory(&exp, sizeof(uint64_t));
		xored_data = exp ^ (subkey[i] >> 16);

        //ft_putendl("=== subkey[i] ===");
		//ft_print_memory(&subkey[i], sizeof(uint64_t));

//        ft_putendl("=== xored ===");
		//	ft_print_memory(&xored_data, sizeof(uint64_t));
		tmp_left = *r_block;

		// xored_data and above are correct
		// compare value of sbox result and left block

		apply_sbox(xored_data, &sbox_result);

		uint64_t t = sbox_result;
		t = t << 32;
		sbox_result = permute(t, per, 32) >> 32;

//        ft_putendl("=== sbox ===");
//		ft_print_memory(&sbox_result, sizeof(uint32_t));
//        ft_putendl("=== left ===");
//		ft_print_memory(l_block, sizeof(uint32_t));

		*r_block = *l_block ^ sbox_result;
//        ft_putendl("=== xored sbox ===");
//		ft_print_memory(r_block, sizeof(uint32_t));
		*l_block = tmp_left;
		i--;
	}
}

static uint64_t    convert_8_to_64(uint8_t *buf)
{
	size_t        i;
	uint64_t    tmp;

	i = 0;
	tmp = 0;
	while (i < 8)
	{
		tmp = (tmp << 8) | *(buf + i);
		i++;
	}
	return (tmp);
}

/*
** reste a gerer le reste / padding quand l'entry n'est pas multiple
 */
static void des_core(char *plain_text, uint64_t subkey[16], uint8_t *result, t_cipher_mode mode)
{
	uint8_t		block[8];
	uint64_t	data;

	ft_memset(block, 0, 8);
	ft_memcpy(block, plain_text, 8);
	data  = convert_8_to_64((uint8_t*)block);

	// Initial permutation
//	ft_putendlcol(SH_YELLOW, "BLOCK BEGIN");
//	ft_print_memory(&block, sizeof(uint64_t));

	data = permute(data, initial_perm, 64);

//    ft_putendl("=== init permute block ===");
//	ft_print_memory(&data, sizeof(uint64_t));

	// Block splitting
	uint32_t l_block = data >> 32;
	uint32_t r_block = data & 0xFFFFFFFF;

	// Round
	if (mode == CIPHER_ENCODE)
		encryption_round(&l_block, &r_block, subkey);
	else if (mode == CIPHER_DECODE)
		decryption_round(&l_block, &r_block, subkey);

	// Concat left / right
	data = ((uint64_t)r_block << 32) | (l_block & 0xFFFFFFFFFFFFFFFF);

	// Final permutation
	data = permute(data, final_perm, 64);

//	ft_putendlcol(SH_YELLOW, "=========END OF BLOCK==========");
//	ft_print_memory(&data, sizeof(uint64_t));
	data = swap_uint64(data);
	ft_memcpy(result, &data, 8);
//	ft_putendlcol(SH_BLUE, "====== end for this block ======\n");
}

static const char g_convert[16] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

static void                hexastring_to_uint64(char *str, uint64_t *key)
{
	char            c;
	size_t            i;
	size_t            len;

	i = 0;
	*key = 0;
	c = 0;
	len = ft_strlen(str);
	while (i < 16)
	{
		if (i >= len)
			c = 0;
		else if (ft_toupper(str[i]) >= 48 && ft_toupper(str[i]) <= 57)
			c = g_convert[(ft_toupper(str[i]) - 48)];
		else if (ft_toupper(str[i]) >= 65 && ft_toupper(str[i]) <= 70)
			c = g_convert[(ft_toupper(str[i]) - 55)];
		*key = (*key << 4) | (uint64_t)c;
		i++;
	}
}

static void des_ecb_encode(t_des des, char *entry)
{
	uint64_t	key;
	size_t		padd;
	size_t		len;
	uint8_t		*cipher;
	char		*padded_input;
	uint64_t	subkey[16];

	hexastring_to_uint64(des.hexa_key, &key);
	key = permute(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);

	len = ft_strlen(entry);
	padd = 8 - (len % 8);
	padded_input = (char*)ft_memalloc(len + padd);
	cipher = (uint8_t*)ft_memalloc(len + padd);
	ft_memcpy(padded_input, entry, len);
	ft_memset(padded_input + len, (int)padd, padd);

	size_t i;
	i = 0;
	len += padd;
	while (i < len)
	{
		des_core(&padded_input[i], subkey, &cipher[i], CIPHER_ENCODE);
		i += 8;
	}
	write(1, cipher, len);
	ft_memdel((void**)&cipher);
	ft_memdel((void**)&padded_input);
}

static void des_ecb_decode(t_des des, char *entry)
{
	uint64_t	key;
	size_t		len;
	uint8_t		*decipher;
	uint64_t	subkey[16];

	hexastring_to_uint64(des.hexa_key, &key);
	key = permute(key, g_keyp, 56);
	des_subkey_generation(key, &subkey);

	len = ft_strlen(entry);
	if (len % 8){
		ft_putstr_fd("error3", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	decipher = (uint8_t*)ft_memalloc(len);
	size_t i;
	i = 0;
//	ft_putstr("|");
//	ft_putstr(entry);
//	ft_putstr("|\n");
	while (i < len)
	{
		des_core(&entry[i], subkey, &decipher[i], CIPHER_DECODE);
		i += 8;
	}
	write(1, decipher, len);
	ft_putchar('\n');
	ft_memdel((void**)&decipher);
}

static void des_cbc_encode(t_des des, char *entry)
{
	(void)des;
	(void)entry;
}

static void des_cbc_decode(t_des des, char *entry)
{
	(void)des;
	(void)entry;
}

static void des_cipher(t_des des, t_cmd_type cmd, char *entry)
{
	if (cmd == DES_ECB && des.cipher_mode == CIPHER_ENCODE)
		des_ecb_encode(des, entry);
	else if (cmd == DES_CBC && des.cipher_mode == CIPHER_ENCODE)
		des_cbc_encode(des, entry);
	else if (cmd == DES_ECB && des.cipher_mode == CIPHER_DECODE)
		des_ecb_decode(des, entry);
	else if (cmd == DES_CBC && des.cipher_mode == CIPHER_DECODE)
		des_cbc_decode(des, entry);
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
	if (des.passwd != NULL)
		ft_strdel(&des.passwd);
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
		des_cipher(des, cmd, entry);
		ft_strdel(&entry);
		return des_end(des, opt, CMD_SUCCESS, NULL);
	}
	des_cipher(des, cmd, av[opt->end]);
	return des_end(des, opt, CMD_SUCCESS, NULL);
}
