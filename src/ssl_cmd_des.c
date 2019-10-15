/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_des.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/09/13 13:14:26 by abara             #+#    #+#             */
/*   Updated: 2019/10/15 16:53:50 by banthony         ###   ########.fr       */
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

// SubKey compression Table
static const  int key_comp[48]=
{    14,17,11,24,1,5,
	  3,28,15,6,21,10,
	  23,19,12,4,26,8,
	  16,7,27,20,13,2,
	  41,52,31,37,47,55,
	  30,40,51,45,33,48,
	  44,49,39,56,34,53,
	  46,42,50,36,29,32
};

// End of round permutation
static const int per[32]=
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
static const int final_perm[64]=
{    40,8,48,16,56,24,64,32,
		 39,7,47,15,55,23,63,31,
		 38,6,46,14,54,22,62,30,
		 37,5,45,13,53,21,61,29,
		 36,4,44,12,52,20,60,28,
		 35,3,43,11,51,19,59,27,
		 34,2,42,10,50,18,58,26,
		 33,1,41,9,49,17,57,25
};


/*static void    print_bits(uint64_t octet, int bits)
{
	int i = -1;
	ft_print_memory(&octet, sizeof(octet));
	octet = swap_uint64(octet);
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

#include <assert.h>
static uint64_t    bits64_permutation(uint64_t source, uint32_t size, const uint32_t *permutation_table)
{
	uint32_t    i;
	uint64_t    result;

	i = 0U;
	result = 0U;
	assert(size <= 64 && size);
	while (i < size)
	{
		if (source & (0x1UL << (size - (permutation_table[i]))))
			result |= (uint64_t)(0x1UL << ((uint32_t)size - 1UL - i));
		i++;
	}
	return (result);
}

static uint64_t        permute_block(const uint8_t *map, uint64_t block, size_t limit)
{
	uint64_t    permuted;
	uint64_t    bit;
	uint8_t        i;

	i = 0;
	permuted = 0;
	while (i < limit)
	{
		bit = ((block >> (64 - map[i])) & 1);
		permuted |= (bit << (64 - (i++ + 1)));
	}
	return (permuted);
}

static void    permute2(uint64_t ptr, uint64_t *trans, const int *matrix, int size)
{
	int    i;

	i = 0;
	*trans = 0;
	while (i < size)
	{
		if (((ptr << (matrix[i] - 1)) & FIRST_BIT_64) != 0)
			*trans += (FIRST_BIT_64 >> i);
		i++;
	}
}

static uint64_t permute(uint64_t data, const int *matrix, int size)
{
//	int i;
	uint64_t permuted_data;
//	char bit_value;

	permute_block((const uint8_t*)matrix, data, (size_t)size);
	permuted_data = bits64_permutation(data, (uint32_t)size, (const uint32_t*)matrix);
	permuted_data = 0;
/*	i = -1;
	while (++i < size)
	{
		bit_value = (data & (1UL << (matrix[i] - 1))) == 0;
		if (bit_value != 0)
			permuted_data &= ~(1UL << i);
		else
			permuted_data |= (1UL << i);
	}*/
	permute2(data, &permuted_data, matrix, size);
//	print_bits(permuted_data, 56);
//	printf("INITIAL:%llu" "VALUE:%llu" "\n", (unsigned long long) data,
//		   (unsigned long long)permuted_data);

	return (permuted_data);
}

/*void    function_extension(uint32_t right, uint64_t *ext)
{
	int    i;

	i = 0;
	*ext = 0;
	while (i < 48)
	{
		if ((right & (FIRST_BIT_32 >> (expansion[i] - 1))) != 0)
			*ext += (FIRST_BIT_64 >> (i + 16));
		i++;
	}
}*/

static void encryption_round(uint32_t *l_block, uint32_t *r_block, uint64_t subkey[16])
{
	int			i;
	uint64_t	xored_data;
	uint32_t	sbox_result;

	i = -1;
	while (++i < 16)
	{
		ft_putendl("========= SLICE ==========");
//		ft_print_memory(l_block, sizeof(uint32_t));
//		ft_print_memory(r_block, sizeof(uint32_t));

		// Right block Expansion to 48 bits
//		ft_putendlcol(SH_YELLOW, "RIGHT BLOCK EXPANSION");
		uint64_t right = *r_block;
		uint64_t tmp = permute(right << 32, expansion, 48);
		tmp = tmp >> 16;
		ft_putendlcol(SH_GREEN, "=========RIGHT PERMUTE==========");
		ft_print_memory(&tmp, sizeof(uint64_t));

		// XOR the result with the sub key corresponding to this round number
		xored_data = tmp ^ (subkey[i] >> 16);
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

		ft_putendlcol(SH_GREEN, "=============================");
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
static void des_encrypt(uint8_t *plain_text, uint64_t subkey[16])
{

	uint8_t		block[9];
	uint64_t	data;

	ft_memset(block, 0, 9);
	ft_memcpy(block, plain_text, 8);
	data  = convert_8_to_64((uint8_t*)block);

//	if (!data)
//		return ;

	// Initial permutation
	ft_putendlcol(SH_YELLOW, "INITIAL PERMUTATION");
	ft_putendl("==== BEFORE ====");
	ft_print_memory(&data, sizeof(uint64_t));
	data = permute(data, initial_perm, 64);
	ft_putendl("==== AFTER ====");
	ft_print_memory(&data, sizeof(uint64_t));

	// Block splitting
	uint32_t l_block = data >> 32;
	uint32_t r_block = data & 0xFFFFFFFF;

//	ft_putendlcol(SH_YELLOW, "\nLEFT BLOCK");
//	ft_print_memory(&l_block, sizeof(uint32_t));
//	ft_putendlcol(SH_YELLOW, "RIGHT BLOCK");
//	ft_print_memory(&r_block, sizeof(uint32_t));

	// Round
	encryption_round(&l_block, &r_block, subkey);

//	ft_putendl("=========END OF ROUND==========");
//	ft_print_memory(&l_block, sizeof(uint32_t));
//	ft_print_memory(&r_block, sizeof(uint32_t));

	// Concat left / right
	data = ((uint64_t)r_block << 32) | (l_block & 0xFFFFFFFFFFFFFFFF);

	// Final permutation
	(void)final_perm;
//	ft_putendlcol(SH_YELLOW, "FINAL PERMUTATION");
	data = permute(data, final_perm, 64);

	ft_putendlcol(SH_YELLOW, "=========END OF BLOCK==========");
	ft_print_memory(&data, sizeof(uint64_t));
	ft_memcpy(plain_text, &data, 8);
//	ft_putendlcol(SH_BLUE, "====== end for this block ======\n");
}

static const int shift_table[16]=
{
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

/*static const int bits_table[64] =
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
};*/

static const int key_right[28] =
{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27,
};

static const int key_left[28] =
{
	28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 55,
};

# define FIRST_BIT_32   0x80000000

static void        rotate_left_28(uint32_t *ptr, int shift)
{
	int i;

	i = -1;
	while (++i < shift)
	{
		*ptr <<= 1;
		if (((*ptr << 3) & FIRST_BIT_32) != 0)
			*ptr += (FIRST_BIT_32 >> 31);
	}
}

static void des_subkey_generation(uint64_t key, uint64_t (*subkey)[16])
{
	int			i;
	uint32_t	l_block = 0;
	uint32_t	r_block = 0;
	uint64_t	block_cat = 0;

	(void)key_right;
	(void)key_left;
	(void)key_comp;
	(void)g_keyp;

//	ft_putendlcol(SH_GREEN, "SUB KEY DEBUG");
//	ft_print_memory(&key, sizeof(uint64_t));

	uint64_t keys = key >> 8;

	r_block = (((1u << 28) - 1)) & keys;
	l_block = ( (((1u << 28) - 1)) & (keys >> 28));
//	ft_print_memory(&r_block, sizeof(uint32_t));
//	ft_print_memory(&l_block, sizeof(uint32_t));

	i = -1;
	while (++i < 16)
	{
		rotate_left_28(&l_block, shift_table[i]);
		rotate_left_28(&r_block, shift_table[i]);

//		ft_putendl("===SUBKEY ROTATE:====");
//		ft_print_memory(&r_block, sizeof(uint32_t));
//		ft_print_memory(&l_block, sizeof(uint32_t));

		block_cat = ( (((1u << 28) - 1)) & r_block);
		block_cat |= ( (((1u << 28) - 1)) & (uint64_t)l_block) << 28;
		block_cat = block_cat << 8;
//		ft_putendl("===CONCAT:");
//		ft_print_memory(&block_cat, sizeof(uint64_t));

		uint64_t tmpkey = permute(block_cat, key_comp, 48);
		(*subkey)[i] = tmpkey;
//		ft_putendl("===PERMUTE:");
//		ft_print_memory(&tmpkey, sizeof(uint64_t));
	}
	(void)key;
	(void)subkey;
}

static const char g_convert[16] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

static void                convert_des(char *str, uint64_t *key)
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

static void des_cipher(t_des des, t_cmd_type cmd, char *entry)
{
	(void)des;
	(void)cmd;

	uint64_t	key;
	size_t		padd;
	size_t		len;
	uint8_t		*cipher;

	convert_des(des.hexa_key, &key);
//	key = 0x133457799BBCDFF1;


//	print_bits(key, 64);
//	printf("%llx", key);

	// Building cipher variable
	len = ft_strlen(entry);
	padd = 8 - (len % 8);
	cipher = (uint8_t*)ft_memalloc(len + padd);
	ft_memset(cipher, 0, len);
	ft_memcpy(cipher, entry, len);
//	printf("ENTRY:%s - ENTRY_LEN:%zu\nDATA:%s - PADD:%zu - DATA_LEN:%zu\n\n",
//		   entry, len, cipher, padd, len + padd);

	// Key permutation, keep 56 bits
	ft_print_memory(&key, sizeof(uint64_t));
	ft_putendlcol(SH_YELLOW, "\nKEY PERMUTATION");
	key = permute(key, g_keyp, 56);
	ft_print_memory(&key, sizeof(uint64_t));
//	print_bits(key, 16);

	// Sub key computing
	uint64_t subkey[16];
	des_subkey_generation(key, &subkey);

	size_t i;
	i = 0;
	len += padd;
//	ft_putendlcol(SH_YELLOW, "\n====== ENCRYPT ROUTINE ======\n");
	while (i < len)
	{
		des_encrypt(&cipher[i], subkey);
		i += 8;
	}

//	ft_putendlcol(SH_YELLOW, "====== ENCRYPTION DONE ======");
//	ft_putstrcol(SH_GREEN, "RESULT:");
	write(1, "Salted__", 8);
	write(1, des.salt, 8);
	write(1, cipher, len);
//	write(1, "\n", 1);
	// Free
	ft_memdel((void**)&cipher);
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
//	ft_print_memory(result, 32);
	if (!des->i_vector)
		des->i_vector = ft_strsub(result, 24, 32);
//	ft_putstr("\nsalt =\t");
//	ft_putendl(des->salt);
//	ft_putstr("key =\t");
//	ft_putendl(des->hexa_key);
//	ft_putstr("iv =\t");
//	ft_putendl(des->i_vector);
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
//	if (des.hexa_key != NULL)
//		ft_strdel(&des.hexa_key);
	if (des.passwd != NULL)
		ft_strdel(&des.passwd);
//	if (des.i_vector != NULL)
//		ft_strdel(&des.i_vector);
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
