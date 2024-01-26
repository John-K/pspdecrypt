CC=clang
CXX=clang++
#EXTRA_FLAG= -lprofiler
EXTRA_FLAG=
CFLAGS=-O3 -Wno-deprecated-declarations
CXXFLAGS=-O3 -Wno-deprecated-declarations

BIN=pspdecrypt
LIBKIRK_SRCS=$(wildcard libkirk/*.c)
OBJS=libLZR.o kl4e.o common.o syscon_ipl_keys.o ipl_decrypt.o pspdecrypt_lib.o PrxDecrypter.o pspdecrypt.o PsarDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(EXTRA_FLAG) -o $@ $(OBJS) -lz -lcrypto

.PHONY: clean
clean:
	-rm -f $(BIN) $(OBJS)
