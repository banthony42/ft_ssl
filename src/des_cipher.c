/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cipher.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 14:59:41 by banthony          #+#    #+#             */
/*   Updated: 2019/10/18 15:28:37 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"
#include "message_digest.h"

void	des_ecb_encode(t_des des, char *entry, size_t size, uint64_t subkey[16])
{
	size_t		padd;
	size_t		len;
	uint8_t		*cipher;
	char		*padded_input;
	size_t		i;

	len = (size == 0) ? ft_strlen(entry) : size;
	padd = 8 - (len % 8);
	padded_input = (char*)ft_memalloc(len + padd);
	cipher = (uint8_t*)ft_memalloc(len + padd);
	ft_memcpy(padded_input, entry, len);
	ft_memset(padded_input + len, (int)padd, padd);
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
	(void)des;
}

void	des_ecb_decode(t_des des, char *entry, size_t size, uint64_t subkey[16])
{
	size_t		len;
	uint8_t		*decipher;
	size_t		i;

	i = 0;
	len = (size == 0) ? ft_strlen(entry) : size;
	if (len % 8)
	{
		ft_putstr_fd("error3", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	decipher = (uint8_t*)ft_memalloc(len);
	while (i < len)
	{
		des_core(&entry[i], subkey, &decipher[i], CIPHER_DECODE);
		i += 8;
	}
	len = get_padding_to_remove(decipher, len);
	write(1, decipher, len);
	ft_memdel((void**)&decipher);
	(void)des;
}

void	des_cbc_encode(t_des des, char *entry, size_t size, uint64_t subkey[16])
{
	(void)subkey;
	(void)size;
	(void)des;
	(void)entry;
}

void	des_cbc_decode(t_des des, char *entry, size_t size, uint64_t subkey[16])
{
	(void)subkey;
	(void)size;
	(void)des;
	(void)entry;
}
