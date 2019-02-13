/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: banthony <banthony@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 19:54:21 by banthony          #+#    #+#             */
/*   Updated: 2019/02/19 20:18:13 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int		find_key(char **av, int ac, char *key)
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

char	*read_cat(int fd)
{
	ssize_t	ret;
	char	*file;
	char	buf[MAXBYTE];

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
		ft_strjoin_replace(&file, buf);
	}
	return (file);
}

char	*read_file(char *path)
{
	int		fd;
	char	*file;

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
	if (!(file = read_cat(fd)))
		return (NULL);
	if (close(fd) < 0)
	{
		ft_putstr(path);
		ft_putendl(" : error on closing fd");
	}
	return (file);
}
