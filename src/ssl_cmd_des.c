/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/09/27 17:25:41 by banthony         ###   ########.fr       */
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

static const int g_keyp[56]=
{   57,49,41,33,25,17,9,
	1,58,50,42,34,26,18,
	10,2,59,51,43,35,27,
	19,11,3,60,52,44,36,
	63,55,47,39,31,23,15,
	7,62,54,46,38,30,22,
	14,6,61,53,45,37,29,
	21,13,5,28,20,12,4
};

//Initial Permutation Table
static const int initial_perm[64]=
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
static const int expansion[48]=
{
	32,1,2,3,4,5,4,5,
	6,7,8,9,8,9,10,11,
	12,13,12,13,14,15,16,17,
	16,17,18,19,20,21,20,21,
	22,23,24,25,24,25,26,27,
	28,29,28,29,30,31,32,1
};
/*
static void    print_bits(uint64_t octet, int bits)
{
	int i = -1;

	ft_putstr("Bit de poid fort -->");
	while (++i < bits)
	{
		if (!(i % 8) && i)
			ft_putstr(" ");
		ft_putnbr((int)(octet & 1));
		ft_putstr(SH_WHITE);
		octet >>= 1;
	}
	ft_putstr("<-- Bit de poid faible");
	ft_putchar('\n');
}*/

static uint64_t permute(uint64_t data, const int *matrix, int size)
{
	int i;
	uint64_t permuted_data;
	char bit_value;

	permuted_data = 0;
	i = -1;
	while (++i < size)
	{
		bit_value = (data & (1UL << (matrix[i] - 1))) == 0;
		if (bit_value != 0)
			permuted_data &= ~(1UL << i);
		else
			permuted_data |= (1UL << i);
	}
	ft_putendl("==== PERMUTED DATA ====");
	ft_print_memory(&permuted_data, sizeof(uint64_t));
//	ft_putendl("==== PERMUTED DATA BITS ====");
//	print_bits(permuted_data, 56);
//	printf("INITIAL:%llu" "VALUE:%llu" "\n", (unsigned long long) data,
//		   (unsigned long long)permuted_data);
	return (permuted_data);
}

static void encryption_round(uint32_t l_block, uint32_t r_block, uint64_t subkey[16])
{
	int			i;
	uint64_t	xored_data;
	i = -1;
	while (++i < 16)
	{
		// Right block Expansion to 48 bits
//		ft_putendlcol(SH_YELLOW, "RIGHT BLOCK EXPANSION");
//		permute(r_block, expansion, 32);
		(void)expansion;
		// XOR the result with the sub key corresponding to this round number
		xored_data = r_block ^ subkey[i];
	}
	(void)l_block;
}

static void des_encrypt(char *plain_text, uint64_t subkey[16])
{

	char		block[9];
	uint64_t	data;

	ft_memset(block, 0, 9);
	ft_strncpy(block, plain_text, 8);
	if (ft_strlen(block))
		ft_putendlcol(SH_GREEN, block);
	else
		ft_putendlcol(SH_GREEN, "[EMPTY BLOCK]");
	ft_memcpy(&data, block, 8);

	// Initial permutation
	ft_putendlcol(SH_YELLOW, "INITIAL PERMUTATION");
	data = permute(data, initial_perm, 64);

	// Block splitting
	uint32_t l_block = 0;
	uint32_t r_block = 0;

	// use binary mask instead
	ft_putendlcol(SH_YELLOW, "\nLEFT BLOCK");
	ft_memcpy(&l_block, &data, sizeof(uint32_t));
	ft_print_memory(&l_block, sizeof(uint32_t));
	data >>= 32;
	ft_putendlcol(SH_YELLOW, "RIGHT BLOCK");
	ft_memcpy(&r_block, &data, sizeof(uint32_t));
	ft_print_memory(&r_block, sizeof(uint32_t));

	encryption_round(l_block, r_block, subkey);
	ft_putendlcol(SH_BLUE, "====== end for this block ======\n");
}

static const int shift_table[16]=
{
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

static const int bits_table[64] =
{
	1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 55, 56,
	57, 58, 59, 60, 61, 62, 63,
	64,
};

static unsigned createMask(unsigned a, unsigned b)
{
	unsigned r = 0;
	for (unsigned i=a; i<=b; i++)
		r |= 1 << i;

	return r;
}

static void des_subkey_generation(uint64_t key, uint64_t (*subkey)[16])
{
	int			i;
	uint32_t	l_block = 0;
	uint64_t	r_block = 0;
	uint64_t	block_cat = 0;

	i = -1;
	ft_putendlcol(SH_YELLOW, "COMPUTING ALL SUBKEY");
	ft_print_memory(&key, sizeof(uint64_t));
	(void)block_cat;
	(void)bits_table;
	l_block |= createMask(0, 28) & key;//0x0000000FFFFFFF & key;
	uint64_t mask = (((1UL << 28) - 1) << 28);
	r_block |= mask & key;//0xFFFFFFF0000000 & key;
	r_block >>= 24;
	ft_print_memory(&l_block, sizeof(uint32_t));
	ft_print_memory(&r_block, sizeof(uint64_t));
	while (++i < 16)
	{
		l_block = rotate_left(l_block, (uint32_t)shift_table[i]);
//		r_block = rotate_left(r_block, (uint32_t)shift_table[i]);
	}
	(void)key;
	(void)subkey;
}

static void des_cipher(t_des des, t_cmd_type cmd, char *entry)
{
	(void)des;
	(void)cmd;

	uint64_t	key;
	size_t		padd;
	size_t		len;
	char		*cipher;

	key = 0x123456ABCD123456;

	// Building cipher variable
	len = ft_strlen(entry);
	padd = 8 - (len % 8);
	cipher = ft_strnew(len + padd);
	ft_memset(cipher, 0, len);
	ft_strncpy(cipher, entry, len);
	printf("ENTRY:%s - ENTRY_LEN:%zu\nDATA:%s - PADD:%zu - DATA_LEN:%zu\n\n",
		   entry, len, cipher, padd, len + padd);

	// Key permutation, keep 56 bits
	ft_putendlcol(SH_YELLOW, "\nKEY PERMUTATION");
	key = permute(key, g_keyp, 56);

	// Sub key computing
	uint64_t subkey[16];
	des_subkey_generation(key, &subkey);

	size_t i;

	i = 0;
	len += padd;
	ft_putendlcol(SH_YELLOW, "\n====== ENCRYPT ROUTINE ======\n");
	while (i < len)
	{
		des_encrypt(&cipher[i], subkey);
		i += 8;
	}

	ft_putendlcol(SH_YELLOW, "====== ENCRYPTION DONE ======");
	ft_putstrcol(SH_GREEN, "RESULT:");
	ft_putendl(cipher);
	// Free
	ft_strdel(&cipher);
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
	ft_strdel(&result);
	return (true);
}

// Use getpassphrase instead. (getpass not secure)
static t_bool	get_pass(t_des *des)
{
	char	user_passwd[PASSWORD_MAX];
	char	check_passwd[PASSWORD_MAX];

	if (!des->passwd)
	{
		ft_memset(user_passwd, 0, PASSWORD_MAX);
		ft_memset(check_passwd, 0, PASSWORD_MAX);
		ft_strncpy(user_passwd, getpass("Enter decryption password:"), PASSWORD_MAX);
		ft_strncpy(check_passwd, getpass("Verifying - Enter decryption password:"), PASSWORD_MAX);
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
	if (des.hexa_key != NULL)
		ft_strdel(&des.hexa_key);
	if (des.passwd != NULL)
		ft_strdel(&des.passwd);
	if (des.i_vector != NULL)
		ft_strdel(&des.i_vector);
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
