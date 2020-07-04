CC=clang
CXX=clang++

BIN=pspdecrypt
LIBKIRK_SRCS=$(wildcard libkirk/*.c)
OBJS=pspdecrypt.o PrxDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)

all: $(BIN)

$(BIN): $(OBJS)
	clang++ -o $@ $(OBJS)
