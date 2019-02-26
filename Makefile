#******************************************************************************#
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: banthony <banthony@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/02/08 12:54:17 by banthony          #+#    #+#              #
#    Updated: 2019/02/26 19:39:56 by banthony         ###   ########.fr        #
#                                                                              #
#******************************************************************************#

NAME = ft_ssl

OBJ_PATH = ./obj/

PATH_SRC = ./src/

PATH_HEAD = ./include/

HEADER_FILE = ft_ssl.h	\

SRC_FILE +=	main.c
SRC_FILE +=	ssl_cmd_dispatcher.c
SRC_FILE += ssl_parser.c
SRC_FILE += ssl_utils.c
SRC_FILE += ssl_cmd_md5.c
SRC_FILE += ssl_cmd_sha256.c
SRC_FILE += ssl_cmd_test.c
SRC_FILE += bits_operations.c
SRC_FILE += md5_hash.c
SRC_FILE += md5_function.c
SRC_FILE += sha256_hash.c


SRC = $(SRC_FILE:%c=$(PATH_SRC)%c)
INCLUDE = $(HEADER_FILE:%h=$(PATH_HEAD)%h)

OBJ = $(SRC_FILE:.c=.o)
OBJ2 = $(OBJ:%.o=$(OBJ_PATH)%.o)

UNAME := $(shell uname)

LIBFT = ./libft

LIBFT_NAME = -L $(LIBFT) -lft
LIBFT_NAME_SANIT = -L $(LIBFT) -lft_sanit

ifeq ($(UNAME), Linux)
MLX_LIB = ./minilibx_linux/
HEAD_DIR = -I ./include -I $(LIBFT)
FLAGS = -Wall -Wextra -Werror
endif

ifeq ($(UNAME), Darwin)
HEAD_DIR = -I ./include -I $(LIBFT)
FLAGS = -Wall -Wextra -Werror -Weverything
endif

DEBUG = -g3 -fsanitize=address

TRASH = Makefile~		\
		./src/*.c~		\
		./include/*.h~	\
		./map/*.txt~	\

all: $(NAME)

$(NAME): $(SRC) $(INCLUDE)
	make -C $(LIBFT) sanit
	gcc $(FLAGS) $(HEAD_DIR) -c $(SRC) $(DEBUG)
	mkdir -p $(OBJ_PATH)
	mv $(OBJ) $(OBJ_PATH)
	gcc $(FLAGS) $(OBJ2) $(HEAD_DIR) $(LIBFT_NAME_SANIT) -o $(NAME) $(DEBUG)

normal: $(SRC) $(INCLUDE)
	make -C $(LIBFT)
	gcc $(FLAGS) $(HEAD_DIR) -c $(SRC)
	mkdir -p $(OBJ_PATH)
	mv $(OBJ) $(OBJ_PATH)
	gcc $(FLAGS) $(OBJ2) $(HEAD_DIR) $(LIBFT_NAME) -o $(NAME)


clean:
	make clean -C $(LIBFT)
	rm -rf $(OBJ_PATH) $(TRASH)

fclean: clean
	make fclean -C $(LIBFT)
	rm -f $(NAME)
	-rm $(OBJ)

re: fclean all
