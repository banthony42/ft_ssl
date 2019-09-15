/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:54:21 by banthony          #+#    #+#             */
/*   Updated: 2019/09/15 12:07:40 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int open_file(const char *file, int flags, char *error)
{
	int fd;

	if ((fd = open(file, flags, S_IRWXU)) < 0)
		ft_putendl(error);
	return fd;
}

/*
**	Iteration on t_list while function return true.
*/
void		ft_lstiter_while_true(t_list *lst, void *data, t_list_condition condition)
{
	while (lst != NULL)
	{
		if (condition(lst, data) == false)
			break;
		lst = lst->next;
	}
}

void		free_cmd_opt(void *opt, size_t opt_size)
{
	ft_memdel(&opt);
	(void)opt_size;
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
