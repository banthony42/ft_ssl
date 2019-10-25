/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   cipher_commands.h                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <banthony@student.42.fr>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 12:40:36 by abara             #+#    #+#             */
/*   Updated: 2019/10/25 15:10:21 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CIPHER_COMMANDS_H
# define CIPHER_COMMANDS_H

# include "ft_ssl.h"
# include <pwd.h>

# ifdef __linux__
#  include <limits.h>
#  include <stdint.h>
#  define PASSWORD_MAX _SC_PASS_MAX

# elif __APPLE__
#  define PASSWORD_MAX _PASSWORD_LEN
# endif

# define FIRST_BIT_32   0x80000000
# define FIRST_BIT_64   0x8000000000000000

/*
**	Definit si un algorithme de chiffrage doit decoder ou encoder.
*/
typedef enum		e_cipher_mode
{
	CIPHER_ENCODE,
	CIPHER_DECODE,
}					t_cipher_mode;

/*
**	Default ciphering options.
*/
# define CIPHER_OPTION_MODE "-d;-e"
# define CIPHER_DECODE_MASK 1
# define CIPHER_ENCODE_MASK 1 << 1

# define CIPHER_INPUT_FILE_KEY "-i"
# define CIPHER_OUTPUT_FILE_KEY "-o"

/*
**	************************ BASE64 ************************
*/

# define B64_INPUT_ERROR "base64 command take only one argument."
# define B64_USE_RESULT_AS_OUT -1

/*
**	base64 command only use default ciphering options.
*/

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
	char			*result;
	size_t			result_len;
	char			table[65];
	char			padd[7];
}					t_base64;

typedef struct		s_decode_block
{
	char			char_array[8];
	int				i_0;
	int				i_1;
	int				i_2;
	int				i_3;
}					t_decode_block;

void				base64_cipher(t_base64 *b64, char *entry, size_t elen);

/*
**	************************ DES FAMILY ************************
*/

# define ENTER_PASS "Enter decryption password:"
# define CHECK_PASS "Verifying - " ENTER_PASS

# define DES_OPTS "-d;-e;-a"

# define DES_B64_MASK 1 << 2

# define DES_HEXAKEY_KEY "-k"
# define DES_PASS_KEY "-p"
# define DES_SALT_KEY "-s"
# define DES_INIT_VECTOR_KEY "-v"

# define SALT_LENGTH 16

typedef enum		e_des_mode
{
	ECB,
	CBC,
	PCBC,
}					t_des_mode;

typedef struct		s_des
{
	t_cipher_mode	cipher_mode;
	t_bool			use_b64;
	char			*hexa_key;
	char			*passwd;
	char			salt[SALT_LENGTH];
	char			*i_vector;
	uint8_t			*result;
	size_t			result_len;
	int				in;
	int				out;
}					t_des;

/*
**	DES
*/

void				des_ecb_encode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_ecb_decode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_cbc_encode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_cbc_decode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_ofb_encode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_ofb_decode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_cfb_encode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_cfb_decode_treatment(t_des *des, t_cmd_type cmd,
											char *entry, size_t size);
void				des_ecb_encode(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_ecb_decode(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_cbc_encode(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_cbc_decode(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_ofb_cipher(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_cfb_cipher(t_des *des, char *entry, size_t size,
									uint64_t subkey[16]);
void				des_core(uint64_t data, uint64_t subkey[16],
									uint8_t *result, t_cipher_mode mode);
/*
**	DES utils
*/

size_t				get_padding_to_remove(uint8_t *decipher, size_t len);
void				hexastring_to_uint64(char *str, uint64_t *key);
uint64_t			bits_permutation(uint64_t data, const uint8_t *matrix,
									size_t size);
void				des_substitution(uint64_t input_data, uint32_t *out);
t_bool				get_pass(t_des *des, char *entry, size_t *size);
void				des_subkey_generation(uint64_t key, uint64_t (*subkey)[16]);

#endif
