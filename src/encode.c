/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encode.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/12 19:07:46 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 20:24:38 by banthony         ###   ########.fr       */
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

void		encode64_bendian(size_t size, char *octet)
{
	uint64_t tmp;

	tmp = swap_uint64(size);
	ft_memcpy(octet, &tmp, sizeof(uint64_t));
}

void		encode128_bendian(size_t size, char *octet)
{
	char		data[128];
	uint64_t	p1;
	uint64_t	p2;

	ft_memset(&data, 0, sizeof(data));
	ft_memcpy(data, &size, sizeof(size_t));
	ft_memcpy(&p1, &data[0], sizeof(uint64_t));
	ft_memcpy(&p2, &data[8], sizeof(uint64_t));
	p1 = swap_uint64(p1);
	p2 = swap_uint64(p2);
	ft_memcpy(octet, &p2, sizeof(p2));
	ft_memcpy(&octet[8], &p1, sizeof(p1));
}
