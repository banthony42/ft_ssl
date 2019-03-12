/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bits_operations.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/23 13:32:14 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 19:07:37 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

uint32_t	swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

uint64_t	swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
		| ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
		| ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}

uint32_t	rotate_left(uint32_t value, uint32_t shift)
{
	return ((value << shift) | (value >> (32 - shift)));
}

uint32_t	rotate_right(uint32_t value, uint32_t shift)
{
	return ((value >> shift) | (value << (32 - shift)));
}

uint64_t	rotate_r_64(uint64_t value, uint64_t shift)
{
	return ((value >> shift) | (value << (64 - shift)));
}
