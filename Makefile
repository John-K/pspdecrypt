CC=clang
CXX=clang++

BIN_PSP=pspdecrypt
BIN_PSAR=psardecrypt
LIBKIRK_SRCS=$(wildcard libkirk/*.c)
OBJS_PSP=pspdecrypt.o PrxDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)
OBJS_PSAR=libLZR.o kl4e.o common.o ipl_decrypt.o pspdecrypt_lib.o PrxDecrypter.o psardecrypt.o PsarDecrypter.o $(LIBKIRK_SRCS:%.c=%.o)

ifdef MACBUILD
	STATIC_FLAG=
else
	STATIC_FLAG=-static
endif


all: $(BIN_PSP) $(BIN_PSAR)

$(BIN_PSP): $(OBJS_PSP)
	$(CXX) $(STATIC_FLAG) -o $@ $(OBJS_PSP)

$(BIN_PSAR): $(OBJS_PSAR)
	$(CXX) $(STATIC_FLAG) -o $@ $(OBJS_PSAR) -lz -lcrypto
