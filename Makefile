CC=clang
CXX=clang++
#EXTRA_FLAG= -lprofiler
EXTRA_FLAG=
CFLAGS=-O3
CXXFLAGS=-O3

BIN_PSP=pspdecrypt
BIN_PSAR=psardecrypt
LIBKIRK_SRCS=$(wildcard libkirk/*.c)
OBJS_PSP=pspdecrypt.o PrxDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)
OBJS_PSAR=libLZR.o kl4e.o common.o ipl_decrypt.o pspdecrypt_lib.o PrxDecrypter.o psardecrypt.o PsarDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)

all: $(BIN_PSP) $(BIN_PSAR)

$(BIN_PSP): $(OBJS_PSP)
	$(CXX) $(EXTRA_FLAG) -o $@ $(OBJS_PSP)

$(BIN_PSAR): $(OBJS_PSAR)
	$(CXX) $(EXTRA_FLAG) -o $@ $(OBJS_PSAR) -lz -lcrypto

.PHONY: clean
clean:
	-rm -f $(BIN_PSP) $(BIN_PSAR) *.o
