#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include "crypto/bip39.h"
#include "crypto/hasher.h"
#include "crypto/secp256k1.h"
#include "crypto/ecdsa.h"


int main(void) 
{
  const char *mnemonic = "garden reject beauty inch scissors rifle amazing couch bacon multiply swim poverty impose spray ugly term stamp prevent nothing mutual awful project wrist movie";//mnemonic_generate(256);
  
  
  char *passphrase = "";
  uint8_t bip39seed[512 / 8],privatekey[256/8],checksum[8],publickey[33],pubhash[20];
	printf("%s\n", mnemonic);
	printf("\n");

   	mnemonic_to_seed(mnemonic, passphrase, bip39seed, 0);

	
	printf("privatekey in hex\n\n");
	for(int i=0;i<32;++i){
		privatekey[i]=bip39seed[i];
		printf("%02X",bip39seed[i]);
	}
	printf("\n");
	printf("\n");
	const ecdsa_curve *curve = &secp256k1;
	ecdsa_get_public_key33(curve,privatekey, publickey);
	printf("publickey in hex\n\n");
	for(int i=0;i<33;++i){
		printf("%02X",publickey[i]);
	}
	printf("\n");
	printf("\n");
	ecdsa_get_pubkeyhash(publickey,HASHER_SHA2_RIPEMD,pubhash);
	
	printf("pubhash in hex\n\n");
	for(int i=0;i<20;++i){
		printf("%02X",pubhash[i]);
	}
	



  	return 0;
}