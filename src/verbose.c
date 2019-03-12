/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   verbose.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/12 19:10:02 by banthony          #+#    #+#             */
/*   Updated: 2019/03/12 19:12:07 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "message_digest.h"

void		md5_verbose(t_md5 md5)
{
	if (md5.flags & MD5_OARG_V_PAD || md5.flags & MD5_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)md5.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)md5.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)md5.padding_size + 64);
	}
	if (md5.flags & MD5_OARG_V_BLOCK || md5.flags & MD5_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)md5.block);
	}
}

void		sha32_verbose(t_sha_32 sha)
{
	if (sha.flags & SHA_OARG_V_PAD || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha.padding_size + 64);
	}
	if (sha.flags & SHA_OARG_V_BLOCK || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha.block);
	}
}

void		sha64_verbose(t_sha_64 sha)
{
	if (sha.flags & SHA_OARG_V_PAD || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstrcol(SH_YELLOW, "padding:");
		ft_putnbrendl((int)sha.padding_size);
		ft_putstrcol(SH_YELLOW, "pad with zero:");
		ft_putnbrendl((int)sha.zero_padding);
		ft_putstrcol(SH_YELLOW, "Total:");
		ft_putnbrendl((int)sha.padding_size + 64);
	}
	if (sha.flags & SHA_OARG_V_BLOCK || sha.flags & SHA_OARG_V_ALL)
	{
		ft_putstr("Number of block:");
		ft_putnbrendl((int)sha.block);
	}
}
