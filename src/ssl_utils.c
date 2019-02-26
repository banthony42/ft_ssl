/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:54:21 by banthony          #+#    #+#             */
/*   Updated: 2019/02/26 18:32:25 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

char			*itoa_base_uint32(uint32_t value, int base)
{
	uint32_t	val;
	uint32_t	i;
	uint32_t	len;
	char		*numb;

	i = 0;
	val = value;
	len = 8;
	if (!(numb = (char*)malloc((size_t)(len + 1) * sizeof(char))))
		return (NULL);
	ft_bzero(numb, (size_t)(len + 1) * sizeof(char));
	if (len > 0)
		len--;
	while (i <= len)
	{
		if (val <= 9 || (val % (unsigned int)base) < 10)
			numb[len - i] = (char)((val % (unsigned int)base) + '0');
		else
			numb[len - i] = (char)((val % (unsigned int)base) + ('a' - 10));
		val = val / (unsigned int)base;
		i++;
	}
	return (numb);
}

int				find_key(char **av, int ac, char *key)
{
	int i;

	i = -1;
	while (++i < ac)
	{
		if (av[i] && !ft_strncmp(av[i], key, ft_strlen(key)))
			return (i);
	}
	return (-1);
}

/*
**	This function join data. Malloc with new size,
**	copy byte from dest, and copy byte from buf into new ptr.
*/

static void		*ft_memjoin(void *dst, void *src, size_t dst_size,
							size_t src_size)
{
	unsigned char *tmp;

	if (!(tmp = ft_memalloc(dst_size + src_size)))
		return (NULL);
	ft_memcpy(tmp, dst, dst_size);
	ft_memcpy(&tmp[dst_size], src, src_size);
	return ((void*)tmp);
}

static void		ft_memjoin_replace(void **dst, void *src, size_t *dst_size,
									size_t src_size)
{
	void *tmp;

	tmp = NULL;
	if (dst == NULL || src == NULL)
		return ;
	if (*dst == NULL)
	{
		if (!(*dst = ft_memalloc(src_size)))
			return ;
		ft_memcpy(*dst, src, src_size);
		*dst_size = src_size - 1;
		return ;
	}
	tmp = *dst;
	*dst = ft_memjoin(*dst, src, *dst_size, src_size);
	*dst_size = *dst_size + src_size - 1;
	ft_memdel(&tmp);
}

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
