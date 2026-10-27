CC = gcc
  CFLAGS = -Wall -Wextra -I./include
  SRC_DIR = ./src
  BIN_DIR = ./bin
  
  all:
      $(CC) $(CFLAGS) -o $(BIN_DIR)/program $(SRC_DIR)/main.c

  clean:
      rm -f $(BIN_DIR)/program