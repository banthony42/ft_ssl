/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cmd_man.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abara <marvin@42.fr>                       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/19 15:39:25 by abara             #+#    #+#             */
/*   Updated: 2019/10/28 16:31:23 by banthony         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "cipher_commands.h"

int			usage_man(char *exe, char *cmd_name)
{
	ft_putstr(exe);
	ft_putstr(" ");
	ft_putstr(cmd_name);
	ft_putendl(" [command]");
	return (CMD_SUCCESS);
}

static void	init_curses(void)
{
	initscr();
	start_color();
	init_pair(BORDER_COLOR, COLOR_BLACK, COLOR_WHITE);
	curs_set(0);
	noecho();
	nodelay(stdscr, true);
	keypad(stdscr, TRUE);
}

static void	draw_border(t_vector2 screen)
{
	int i;
	int max;

	i = -1;
	max = screen.x;
	attron(COLOR_PAIR(BORDER_COLOR));
	while (++i < max)
	{
		mvaddch(0, i, '-');
		mvaddch(screen.y - 1, i, '-');
	}
	attroff(COLOR_PAIR(BORDER_COLOR));
}

static void	get_screen(t_vector2 *screen_size)
{
	getmaxyx(stdscr, screen_size->y, screen_size->x);
	if (screen_size->y >= 85 || screen_size->x >= 365)
	{
		endwin();
		ft_putendl("Error : Screen too big !");
	}
	if (screen_size->y <= 20 || screen_size->x <= 20)
	{
		endwin();
		ft_putendl("Error : Screen too small !");
	}
	erase();
}

int			cmd_man(int ac, char **av, t_cmd_type cmd, t_cmd_opt *opt)
{
	int			in;
	t_vector2	screen_size;
	char		*msg;

	msg = ": Press 'q' to quit";
	if (ac != 3)
		usage_man("ft_ssl", "man");
	init_curses();
	while ((in = getch()) != 'q')
	{
		get_screen(&screen_size);
		draw_border(screen_size);
		mvprintw(10, 10, "NAME\n\t\tbase64");
		mvprintw(20, 10, "USAGE");
		mvprintw(30, 10, "DESCRIPTION");
		mvprintw(40, 10, "OPTIONS");
		attron(COLOR_PAIR(BORDER_COLOR));
		mvprintw(screen_size.y - 1, 10, msg);
		attroff(COLOR_PAIR(BORDER_COLOR));
		refresh();
	}
	endwin();
	if (!av | (cmd == MAN) | !opt)
		;
	return (CMD_SUCCESS);
}
