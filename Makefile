CC=clang
CXX=clang++

BIN_PSP=pspdecrypt
BIN_PSAR=psardecrypt
LIBKIRK_SRCS=$(wildcard libkirk/*.c)
OBJS_PSP=pspdecrypt.o PrxDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)
OBJS_PSAR=pspdecrypt_lib.o PrxDecrypter.o psardecrypt.o PsarDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)

all: $(BIN_PSP) $(BIN_PSAR)

$(BIN_PSP): $(OBJS_PSP)
	clang++ -o $@ $(OBJS_PSP)

$(BIN_PSAR): $(OBJS_PSAR)
	clang++ -o $@ $(OBJS_PSAR) -lz
