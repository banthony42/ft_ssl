/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_key_gen.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/16 15:38:03 by banthony          #+#    #+#             */
/*   Updated: 2019/10/18 13:45:58 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

static const uint8_t shift_table[16]=
{
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

// SubKey compression Table
static const  uint8_t key_comp[48]=
{    14,17,11,24,1,5,
	  3,28,15,6,21,10,
	  23,19,12,4,26,8,
	  16,7,27,20,13,2,
	  41,52,31,37,47,55,
	  30,40,51,45,33,48,
	  44,49,39,56,34,53,
	  46,42,50,36,29,32
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

void des_subkey_generation(uint64_t key, uint64_t (*subkey)[16])
{
	int			i;
	uint32_t	l_block = 0;
	uint32_t	r_block = 0;
	uint64_t	block_cat = 0;

	uint64_t keys = key >> 8;

	r_block = (((1u << 28) - 1)) & keys;
	l_block = ( (((1u << 28) - 1)) & (keys >> 28));

	i = -1;
	while (++i < 16)
	{
		rotate_left_28(&l_block, shift_table[i]);
		rotate_left_28(&r_block, shift_table[i]);

		block_cat = ( (((1u << 28) - 1)) & r_block);
		block_cat |= ( (((1u << 28) - 1)) & (uint64_t)l_block) << 28;
		block_cat = block_cat << 8;

		uint64_t tmpkey = bits_permutation(block_cat, key_comp, 48);
		(*subkey)[i] = tmpkey;

	}
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
	if (!des->i_vector)
		des->i_vector = ft_strsub(result, 24, 32);
	ft_strdel(&entry);
	ft_strdel(&result);
	return (true);
}

// Use getpassphrase instead. (getpass not secure)
t_bool	get_pass(t_des *des)
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
