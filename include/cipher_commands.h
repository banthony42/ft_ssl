/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   cipher_commands.h                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 12:40:36 by abara             #+#    #+#             */
/*   Updated: 2019/09/13 11:07:05 by abara            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CIPHER_COMMANDS_H
# define CIPHER_COMMANDS_H

# include "ft_ssl.h"

/*
**	************************ BASE64 ************************
*/

/*
**	BASE64 options & MASK
*/

# define BASE64_OPTS "-d;-e"
# define B64_DECODE_MASK 1
# define B64_ENCODE_MASK 1 << 1

/*
**	Option avec entree utilisateur
*/

# define BASE64_INPUT_FILE_KEY "-i"
# define BASE64_OUTPUT_FILE_KEY "-o"

/*
**	Definit si un algorithme de chiffrage doit decoder ou encoder.
*/
typedef enum		e_cipher_mode
{
	ENCODE,
	DECODE,
}					t_cipher_mode;

/*
**	cipher_mode: Mode de fonctionnement (Encodage ou Decodage)
**	inp_fd:		 Source pour le chiffrage, STDIN par defaut
**	out_fd:		 Sortie pour le chiffrage, STDOUT par defaut
*/
typedef struct		s_base64
{
	t_cipher_mode	cipher_mode;
	t_bool			b64_url;
	int				in;
	int				out;
}					t_base64;

typedef struct		s_decode_block
{
	char			char_array[8];
	int				i_0;
	int				i_1;
	int				i_2;
	int				i_3;
}					t_decode_block;

void				base64_cipher(t_base64 b64, char *entry);

#endif
