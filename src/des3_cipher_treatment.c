/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des3_cipher_treatment.c                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/29 14:43:35 by banthony          #+#    #+#             */
/*   Updated: 2019/10/29 14:55:06 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

void	des3_encode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64		b64;
	t_des3_subkey	subkey;

	(void)cmd;
	des3_generate_keys(des->hexa_key, &subkey);
	des3_encode(des, entry, size, subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = des->out;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, (char*)des->result, des->result_len);
	}
	else
		write(des->out, des->result, des->result_len);
}

void	des3_decode_treatment(t_des *des, t_cmd_type cmd, char *entry,
									size_t size)
{
	t_base64		b64;
	t_des3_subkey	subkey;

	(void)cmd;
	des3_generate_keys(des->hexa_key, &subkey);
	if (des->use_b64)
	{
		ft_memset(&b64, 0, sizeof(b64));
		b64.out = B64_USE_RESULT_AS_OUT;
		b64.in = des->in;
		b64.cipher_mode = des->cipher_mode;
		base64_cipher(&b64, entry, size);
		des3_decode(des, b64.result, b64.result_len, subkey);
		ft_strdel(&b64.result);
	}
	else
		des3_decode(des, entry, size, subkey);
	write(des->out, des->result, des->result_len);
}
