#gcc -E main.c         : main.i
#gcc -S main.c         : main.s
#gcc -c main.c         : main.o
#gcc    main.o -o main : main.exe
#gcc    main.c -o main : main.exe

#all : main.exe

#main.exe : main.o
#	gcc    main.o -o main

#main.o : main.c
#	gcc -c main.c 

CC := gcc

BASE_DIR := ./

SRC_DIR := $(BASE_DIR)

CRYPTO_LIB := $(BASE_DIR)/cryptography

CSRC := $(wildcard $(SRC_DIR)/*.c) 
CSRC +=	$(wildcard $(CRYPTO_LIB)/*.c) 
CSRC += $(wildcard $(CRYPTO_LIB)/aes/*.c)
CSRC += $(wildcard $(CRYPTO_LIB)/chacha20poly1305/*.c)
CSRC += $(wildcard $(CRYPTO_LIB)/ed25519-donna/*.c)

   
OBJ := $(CSRC:.c=.o)


CFLAGS := -L$(CRYPTO_LIB) -I$(CRYPTO_LIB)


inc = 	cryptography/						\
		cryptography/aes/ 				\
		cryptography/ed25519-donna/ 		\
		cryptography/chacha20poly1305/ 	\
		  
 
CFLAGS = $(addprefix -I ,$(inc) )


main:$(CSRC)
	$(CC) -o $@ $^ $(CFLAGS)   

clean : 
	rm $(OBJ) main.exe
