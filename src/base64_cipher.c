/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_cipher.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/26 14:21:32 by abara             #+#    #+#             */
/*   Updated: 2019/09/13 12:16:31 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

/*
	  0 000000 A           17 010001 R           34 100010 i           51 110011 z
      1 000001 B           18 010010 S           35 100011 j           52 110100 0
      2 000010 C           19 010011 T           36 100100 k           53 110101 1
      3 000011 D           20 010100 U           37 100101 l           54 110110 2
      4 000100 E           21 010101 V           38 100110 m           55 110111 3
      5 000101 F           22 010110 W           39 100111 n           56 111000 4
      6 000110 G           23 010111 X           40 101000 o           57 111001 5
      7 000111 H           24 011000 Y           41 101001 p           58 111010 6
      8 001000 I           25 011001 Z           42 101010 q           59 111011 7
      9 001001 J           26 011010 a           43 101011 r           60 111100 8
     10 001010 K           27 011011 b           44 101100 s           61 111101 9
     11 001011 L           28 011100 c           45 101101 t           62 111110 +
     12 001100 M           29 011101 d           46 101110 u           63 111111 /
     13 001101 N           30 011110 e           47 101111 v
     14 001110 O           31 011111 f           48 110000 w        (complément) =
     15 001111 P           32 100000 g           49 110001 x
     16 010000 Q           33 100001 h           50 110010 y
*/
void	base64_cipher(t_base64 b64, char *entry)
{
	char	*output;
	int		entry_len;
	int		padding;

	if (!entry)
		return ;

	// If file input and entry are both present,
	// determine which data will be ciphered.
	ft_putendl_fd(entry, b64.out_fd);

	entry_len = ft_strlen(entry);
	if ((padding = (entry_len * 8) % 24) == 8)
		padding = 4;
	else if (padding == 16)
		padding = 2;
	else
		padding = 0;

	ft_putnbrendl(entry_len);
	int out_len = ( ( (entry_len * 8) + padding) / 6);
	ft_putnbrendl(out_len);

	if (!(output = ft_strnew(out_len)))
		return ;

	ft_strncpy(output, entry, entry_len);

	ft_print_memory(output, out_len);

	int i = 0;
	t_block block_reader;
	ft_putendl("============");
	while (i < out_len)
	{
		ft_memcpy(&block_reader.block, &output[0], 3);
		// block_reader.block_1 = (unsigned char)output[i];
		// block_reader.block_2 = (unsigned char)output[i + 1];
		// block_reader.block_3 = (unsigned char)output[i + 2];

		unsigned char test;
		ft_memcpy(&test, &output[0], 1);
		ft_putnbrendl(test >> 2);
		ft_putnbrendl(test & CODE_MASK);
		ft_putnbrendl(test);
		ft_putendl("============");

		ft_putnbrendl(block_reader.code_a);
		ft_putnbrendl(block_reader.code_b);
		ft_putnbrendl(block_reader.code_c);
		ft_putnbrendl(block_reader.code_d);

		ft_putendl("============");

		break;
	}
	ft_strdel(&output);
}
