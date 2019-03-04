/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha384_function.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/26 19:01:21 by banthony          #+#    #+#             */
/*   Updated: 2019/02/27 18:50:56 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

uint64_t	sha384_func_ch(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (~x & z));
}

uint64_t	sha384_func_maj(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint64_t	sha384_func_sum0(uint64_t x)
{
	return (rotate_right_64(x, 28) ^ rotate_right_64(x, 34) ^ rotate_right_64(x, 39));
}

uint64_t	sha384_func_sum1(uint64_t x)
{
	return (rotate_right_64(x, 14) ^ rotate_right_64(x, 18) ^ rotate_right_64(x, 41));
}

uint64_t	sha384_func_sig0(uint64_t x)
{
	return (rotate_right_64(x, 1) ^ rotate_right_64(x, 8) ^ (x >> 7));
}

uint64_t	sha384_func_sig1(uint64_t x)
{
	return (rotate_right_64(x, 19) ^ rotate_right_64(x, 61) ^ (x >> 6));
}
