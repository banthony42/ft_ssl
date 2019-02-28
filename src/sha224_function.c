/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha224_function.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/26 19:01:21 by banthony          #+#    #+#             */
/*   Updated: 2019/02/27 18:50:56 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "message_digest.h"

uint32_t	sha224_func_ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (~x & z));
}

uint32_t	sha224_func_maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint32_t	sha224_func_sum0(uint32_t x)
{
	return (rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22));
}

uint32_t	sha224_func_sum1(uint32_t x)
{
	return (rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25));
}

uint32_t	sha224_func_sig0(uint32_t x)
{
	return (rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3));
}

uint32_t	sha224_func_sig1(uint32_t x)
{
	return (rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10));
}
