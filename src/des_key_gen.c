/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_key_gen.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/16 15:38:03 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:46:00 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

static t_bool	ft_ishexa(char *str)
{
	int i;

	i = 0;
	if (!str || ft_strlen(str) == 0)
		return (false);
	while (str[i])
	{
		if (!ft_isdigit(str[i]))
			if (ft_toupper(str[i]) < 'A' || ft_toupper(str[i]) > 'F')
				return (false);
		i++;
	}
	return (true);
}

static t_bool	create_key(t_des *des)
{
	char		*result;
	char		*entry;
	size_t		entry_len;
	uint64_t	salt;

	hexastring_to_uint64(des->salt, &salt);
	entry_len = ft_strlen(des->passwd) + 8;
	entry = (char*)ft_memalloc(entry_len);
	ft_memset(entry, 0, entry_len);
	ft_memcpy(entry, des->passwd, ft_strlen(des->passwd));
	ft_memcpy(entry + ft_strlen(des->passwd), &salt, 8);
	if (!(result = md5_digest((unsigned char*)entry, entry_len, 0)) ||
		ft_strlen(result) != 32)
	{
		ft_putendl("An error occured during the creation of the key.");
		ft_memdel((void**)&entry);
		return (false);
	}
	des->hexa_key = ft_strsub(result, 0, 8);
	if (!des->i_vector)
		des->i_vector = ft_strsub(result, 24, 32);
	ft_memdel((void**)&entry);
	ft_strdel(&result);
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
	while (read(fd, buffer, 1))
	{
		if (ft_ishexa(buffer))
			generated_salt[index++] = buffer[0];
		if (index >= SALT_LENGTH)
			break ;
	}
	ft_strncpy(des->salt, generated_salt, SALT_LENGTH);
	return (true);
}

static void		extract_salt(t_des *des, char *entry, size_t *size)
{
	uint64_t	salt;
	char		*salt_str;
	size_t		salt_len;

	if (!ft_strncmp("Salted__", entry, 8))
	{
		salt = *((uint64_t*)(void*)(entry + 8));
		salt_str = ft_itoa_base_uint64(salt, 16);
		if ((salt_len = ft_strlen(salt_str)) != 16)
			ft_memset(des->salt, '0', SALT_LENGTH);
		ft_memcpy(des->salt, salt_str, salt_len);
		free(salt_str);
		*size = *size - 16;
		ft_memmove(entry, entry + SALT_LENGTH, *size);
	}
}

/*
**	Use getpassphrase instead. (getpass not secure)
*/

t_bool			get_pass(t_des *des, char *entry, size_t *size)
{
	char	user_passwd[PASSWORD_MAX];
	char	check_passwd[PASSWORD_MAX];

	if (des->cipher_mode == CIPHER_DECODE)
		extract_salt(des, entry, size);
	if (!des->passwd)
	{
		ft_memset(user_passwd, 0, PASSWORD_MAX);
		ft_memset(check_passwd, 0, PASSWORD_MAX);
		ft_strncpy(user_passwd, getpass(ENTER_PASS), PASSWORD_MAX);
		ft_strncpy(check_passwd, getpass(CHECK_PASS), PASSWORD_MAX);
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
