/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bits_operations.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/23 13:32:14 by banthony          #+#    #+#             */
/*   Updated: 2019/02/23 15:43:27 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void		encode64_lendian(size_t size, char *octet)
{
	octet[0] = (char)((size) & 0x00000000000000ffULL);
	octet[1] = (char)(((size) & 0x000000000000ff00ULL) >> 8);
	octet[2] = (char)(((size) & 0x0000000000ff0000ULL) >> 16);
	octet[3] = (char)(((size) & 0x00000000ff000000ULL) >> 24);
	octet[4] = (char)(((size) & 0x000000ff00000000ULL) >> 32);
	octet[5] = (char)(((size) & 0x0000ff0000000000ULL) >> 40);
	octet[6] = (char)(((size) & 0x00ff000000000000ULL) >> 48);
	octet[7] = (char)(((size) & 0xff00000000000000ULL) >> 56);
}

uint32_t	rotate_left(uint32_t value, uint32_t shift)
{
	return ((value << shift) | (value >> (32 - shift)));
}

uint32_t	rotate_right(uint32_t value, uint32_t shift)
{
	return ((value >> shift) | (value << (32 - shift)));
}

uint32_t	swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}
