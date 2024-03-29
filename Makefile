#******************************************************************************#
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: banthony <banthony@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/02/08 12:54:17 by banthony          #+#    #+#              #
#    Updated: 2019/10/29 15:20:36 by banthony         ###   ########.fr        #
#                                                                              #
#******************************************************************************#

NAME = ft_ssl

OBJ_PATH = ./obj/

PATH_SRC = ./src/

PATH_HEAD = ./include/

HEADER_FILE = ft_ssl.h	\

SRC_FILE +=	main.c
SRC_FILE +=	ssl_dispatcher.c
SRC_FILE += ssl_parser.c
SRC_FILE += ssl_key_value_parser.c
SRC_FILE += ssl_utils.c
SRC_FILE += ssl_read_input.c
SRC_FILE += ssl_cmd_md5.c
SRC_FILE += ssl_cmd_sha.c
SRC_FILE += ssl_cmd_base64.c
SRC_FILE += ssl_cmd_des.c
SRC_FILE += ssl_cmd_test.c
SRC_FILE += bits_operations.c
SRC_FILE += md5_digest.c
SRC_FILE += md5_function.c
SRC_FILE += sha_dispatcher.c
SRC_FILE += sha_digest_32.c
SRC_FILE += sha_digest_64.c
SRC_FILE += sha_function_32.c
SRC_FILE += sha_function_64.c
SRC_FILE += base64_cipher.c
SRC_FILE += base64_utils.c
SRC_FILE += des_key_gen.c
SRC_FILE += des_subkey_gen.c
SRC_FILE += des_cipher.c
SRC_FILE += des3_ofb_cfb.c
SRC_FILE += des_cipher_treatment.c
SRC_FILE += des_ofb_cfb_treatment.c
SRC_FILE += des3_cipher_treatment.c
SRC_FILE += des_core.c
SRC_FILE += des_substitution.c
SRC_FILE += des_utils.c
SRC_FILE += encode.c
SRC_FILE += verbose.c
SRC_FILE += test_parser.c

SRC = $(SRC_FILE:%c=$(PATH_SRC)%c)
INCLUDE = $(HEADER_FILE:%h=$(PATH_HEAD)%h)

OBJ = $(SRC_FILE:.c=.o)
OBJ2 = $(OBJ:%.o=$(OBJ_PATH)%.o)

UNAME := $(shell uname)

LIBFT = ./libft

LIBFT_NAME = -L $(LIBFT) -lft
LIBFT_NAME_SANIT = -L $(LIBFT) -lft_sanit

ifeq ($(UNAME), Linux)
LIB =
HEAD_DIR = -I ./include -I $(LIBFT)
FLAGS = -Wall -Wextra -Werror
endif

ifeq ($(UNAME), CYGWIN_NT-6.1)
LIB =
HEAD_DIR = -I ./include -I $(LIBFT)
FLAGS = -Wall -Wextra -Werror
endif

ifeq ($(UNAME), Darwin)
LIB =
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
	gcc $(FLAGS) -o $(NAME) $(OBJ2) $(HEAD_DIR) $(LIBFT_NAME_SANIT) $(LIB) $(DEBUG)

normal: $(SRC) $(INCLUDE)
	make -C $(LIBFT)
	gcc $(FLAGS) $(HEAD_DIR) $(LIB) -c $(SRC)
	mkdir -p $(OBJ_PATH)
	mv $(OBJ) $(OBJ_PATH)
	gcc $(FLAGS) $(OBJ2) $(HEAD_DIR) $(LIBFT_NAME) -o $(NAME) $(LIB)


clean:
	make clean -C $(LIBFT)
	rm -rf $(OBJ_PATH) $(TRASH)

fclean: clean
	make fclean -C $(LIBFT)
	rm -f $(NAME)
	-rm $(OBJ)

re: fclean all
