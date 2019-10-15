/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   apply_sbox.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/11 15:48:10 by banthony          #+#    #+#             */
/*   Updated: 2019/10/15 10:36:31 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "cipher_commands.h"

static const uint8_t g_sbox[8][4][16] = {{
		{0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
			0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7},
		{0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1,
			0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8},
		{0x4, 0x1, 0xE, 0x8, 0xD, 0x6, 0x2, 0xB,
			0xF, 0xC, 0x9, 0x7, 0x3, 0xA, 0x5, 0x0},
		{0xF, 0xC, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7,
			0x5, 0xB, 0x3, 0xE, 0xA, 0x0, 0x6, 0xD},
	}, {
		{0xF, 0x1, 0x8, 0xE, 0x6, 0xB, 0x3, 0x4,
			0x9, 0x7, 0x2, 0xD, 0xC, 0x0, 0x5, 0xA},
		{0x3, 0xD, 0x4, 0x7, 0xF, 0x2, 0x8, 0xE,
			0xC, 0x0, 0x1, 0xA, 0x6, 0x9, 0xB, 0x5},
		{0x0, 0xE, 0x7, 0xB, 0xA, 0x4, 0xD, 0x1,
			0x5, 0x8, 0xC, 0x6, 0x9, 0x3, 0x2, 0xF},
		{0xD, 0x8, 0xA, 0x1, 0x3, 0xF, 0x4, 0x2,
			0xB, 0x6, 0x7, 0xC, 0x0, 0x5, 0xE, 0x9},
	}, {
		{0xA, 0x0, 0x9, 0xE, 0x6, 0x3, 0xF, 0x5,
			0x1, 0xD, 0xC, 0x7, 0xB, 0x4, 0x2, 0x8},
		{0xD, 0x7, 0x0, 0x9, 0x3, 0x4, 0x6, 0xA,
			0x2, 0x8, 0x5, 0xE, 0xC, 0xB, 0xF, 0x1},
		{0xD, 0x6, 0x4, 0x9, 0x8, 0xF, 0x3, 0x0,
			0xB, 0x1, 0x2, 0xC, 0x5, 0xA, 0xE, 0x7},
		{0x1, 0xA, 0xD, 0x0, 0x6, 0x9, 0x8, 0x7,
			0x4, 0xF, 0xE, 0x3, 0xB, 0x5, 0x2, 0xC},
	}, {
		{0x7, 0xD, 0xE, 0x3, 0x0, 0x6, 0x9, 0xA,
			0x1, 0x2, 0x8, 0x5, 0xB, 0xC, 0x4, 0xF},
		{0xD, 0x8, 0xB, 0x5, 0x6, 0xF, 0x0, 0x3,
			0x4, 0x7, 0x2, 0xC, 0x1, 0xA, 0xE, 0x9},
		{0xA, 0x6, 0x9, 0x0, 0xC, 0xB, 0x7, 0xD,
			0xF, 0x1, 0x3, 0xE, 0x5, 0x2, 0x8, 0x4},
		{0x3, 0xF, 0x0, 0x6, 0xA, 0x1, 0xD, 0x8,
			0x9, 0x4, 0x5, 0xB, 0xC, 0x7, 0x2, 0xE},
	}, {
		{0x2, 0xC, 0x4, 0x1, 0x7, 0xA, 0xB, 0x6,
			0x8, 0x5, 0x3, 0xF, 0xD, 0x0, 0xE, 0x9},
		{0xE, 0xB, 0x2, 0xC, 0x4, 0x7, 0xD, 0x1,
			0x5, 0x0, 0xF, 0xA, 0x3, 0x9, 0x8, 0x6},
		{0x4, 0x2, 0x1, 0xB, 0xA, 0xD, 0x7, 0x8,
			0xF, 0x9, 0xC, 0x5, 0x6, 0x3, 0x0, 0xE},
		{0xB, 0x8, 0xC, 0x7, 0x1, 0xE, 0x2, 0xD,
			0x6, 0xF, 0x0, 0x9, 0xA, 0x4, 0x5, 0x3},
	}, {
		{0xC, 0x1, 0xA, 0xF, 0x9, 0x2, 0x6, 0x8,
			0x0, 0xD, 0x3, 0x4, 0xE, 0x7, 0x5, 0xB},
		{0xA, 0xF, 0x4, 0x2, 0x7, 0xC, 0x9, 0x5,
			0x6, 0x1, 0xD, 0xE, 0x0, 0xB, 0x3, 0x8},
		{0x9, 0xE, 0xF, 0x5, 0x2, 0x8, 0xC, 0x3,
			0x7, 0x0, 0x4, 0xA, 0x1, 0xD, 0xB, 0x6},
		{0x4, 0x3, 0x2, 0xC, 0x9, 0x5, 0xF, 0xA,
			0xB, 0xE, 0x1, 0x7, 0x6, 0x0, 0x8, 0xD},
	}, {
		{0x4, 0xB, 0x2, 0xE, 0xF, 0x0, 0x8, 0xD,
			0x3, 0xC, 0x9, 0x7, 0x5, 0xA, 0x6, 0x1},
		{0xD, 0x0, 0xB, 0x7, 0x4, 0x9, 0x1, 0xA,
			0xE, 0x3, 0x5, 0xC, 0x2, 0xF, 0x8, 0x6},
		{0x1, 0x4, 0xB, 0xD, 0xC, 0x3, 0x7, 0xE,
			0xA, 0xF, 0x6, 0x8, 0x0, 0x5, 0x9, 0x2},
		{0x6, 0xB, 0xD, 0x8, 0x1, 0x4, 0xA, 0x7,
			0x9, 0x5, 0x0, 0xF, 0xE, 0x2, 0x3, 0xC},
	}, {
		{0xD, 0x2, 0x8, 0x4, 0x6, 0xF, 0xB, 0x1,
			0xA, 0x9, 0x3, 0xE, 0x5, 0x0, 0xC, 0x7},
		{0x1, 0xF, 0xD, 0x8, 0xA, 0x3, 0x7, 0x4,
			0xC, 0x5, 0x6, 0xB, 0x0, 0xE, 0x9, 0x2},
		{0x7, 0xB, 0x4, 0x1, 0x9, 0xC, 0xE, 0x2,
			0x0, 0x6, 0xA, 0xD, 0xF, 0x3, 0x5, 0x8},
		{0x2, 0x1, 0xE, 0x7, 0x4, 0xA, 0x8, 0xD,
			0xF, 0xC, 0x9, 0x0, 0x3, 0x5, 0x6, 0xB}}};

void			apply_sbox(uint64_t ext, uint32_t *sbox)
{
	int			i;
	uint32_t	col;
	uint32_t	line;

	i = 2;
	*sbox = 0;
	while (i < 10)
	{
		col = 0;
		line = 0;
		if (((ext << ((6 * i + 5) + 4)) & FIRST_BIT_64) != 0)
			line += 1;
		if (((ext << ((6 * i) + 4)) & FIRST_BIT_64) != 0)
			line += 2;
		if (((ext << ((6 * i + 1) + 4)) & FIRST_BIT_64) != 0)
			col += 8;
		if (((ext << ((6 * i + 2) + 4)) & FIRST_BIT_64) != 0)
			col += 4;
		if (((ext << ((6 * i + 3) + 4)) & FIRST_BIT_64) != 0)
			col += 2;
		if (((ext << ((6 * i + 4) + 4)) & FIRST_BIT_64) != 0)
			col += 1;
		*sbox += (unsigned)(g_sbox[i - 2][line][col]) << (60 - (4 * (i - 2)));
		i++;
	}
}
