/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_read_input.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 15:34:33 by banthony          #+#    #+#             */
/*   Updated: 2019/10/18 15:34:47 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

unsigned char	*read_cat(int fd, size_t *size)
{
	ssize_t			ret;
	unsigned char	*file;
	unsigned char	buf[MAXBYTE];

	ret = 1;
	file = NULL;
	if (fd < 0)
	{
		ft_putendl("read_cat: error fd < 0");
		return (NULL);
	}
	while (ret)
	{
		if ((ret = read(fd, buf, MAXBYTE - 1)) <= 0)
			break ;
		buf[ret] = '\0';
		ft_memjoin_replace((void**)&file, buf, size, (size_t)ret + 1);
		ft_memset(buf, 0, MAXBYTE);
	}
	return (file);
}

unsigned char	*read_file(char *path, size_t *size)
{
	int				fd;
	unsigned char	*file;

	fd = 0;
	if (!path)
	{
		ft_putendl("read_file: path is null");
		return (NULL);
	}
	if ((fd = open(path, O_RDONLY)) < 0)
	{
		ft_putstr("ft_ssl: ");
		ft_putstr(path);
		ft_putendl(" : no such file or directory");
		return (NULL);
	}
	if (!(file = read_cat(fd, size)))
		return (NULL);
	if (close(fd) < 0)
	{
		ft_putstr(path);
		ft_putendl(" : error on closing fd");
	}
	return (file);
}
