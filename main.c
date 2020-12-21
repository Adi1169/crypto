#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include "crypto/bip39.h"


int main(void) 
{
  const char *mnemonic = "garden reject beauty inch scissors rifle amazing couch bacon multiply swim poverty impose spray ugly term stamp prevent nothing mutual awful project wrist movie";//mnemonic_generate(256);
  
  
  char *passphrase = "";
  uint8_t bip39seed[512 / 8];
	printf("%s\n", mnemonic);
	printf("\n");
   mnemonic_to_seed(mnemonic, passphrase, bip39seed, 0);
  	printf("Seed in hex\n\n");
	for(int i=0;i<64;++i){
		printf("%02X",bip39seed[i]);
	}
	
	printf("\n");
  return 0;
}
