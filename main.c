#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha2.h"
#include "ripemd160.h"
int main(void) 
{
  	const char *mnemonic = "garden reject beauty inch scissors rifle amazing couch bacon multiply swim poverty impose spray ugly term stamp prevent nothing mutual awful project wrist movie";//mnemonic_generate(256);
	char *passphrase = "";
	//const char *curve = &secp256k1;
	HDNode master;
	uint8_t bip39seed[512 / 8],publickey[32];
	uint8_t hash[SHA256_DIGEST_LENGTH],address[25],versionkey[21],dhash[SHA256_DIGEST_LENGTH],ripe[RIPEMD160_DIGEST_LENGTH],addresscomp[34];
	
	mnemonic_to_seed(mnemonic, passphrase, bip39seed, 0);
	
	int x=hdnode_from_seed(bip39seed,64,SECP256K1_NAME,&master);
	hdnode_fill_public_key(&master);

	
	sha256_Raw(&master.public_key,sizeof(master.public_key),hash);

	
	ripemd160(hash, sizeof(hash), &ripe);
	
	versionkey[0]=(char)0;
	memcpy(&versionkey[1],ripe,sizeof(ripe));
	
	sha256_Raw(&versionkey,sizeof(versionkey),hash);
	
	sha256_Raw(&hash,sizeof(hash),dhash);

	
	for(int i=0;i<21;++i)address[i]=versionkey[i];
	for(int i=21,j=0;i<25;++i,++j)address[i]=dhash[j];

	
	uint16_t len =(char)34;
	b58enc(addresscomp,&len,address, 25);

	printf("chain code-->");
	for(int i=0;i<32;++i)printf("%02X",master.chain_code[i]);
	printf("\n");
	
	printf("public key-->");
	for(int i=0;i<33;++i){printf("%02X",master.public_key[i]);publickey[i]=master.public_key[i];}
	printf("\n");

	printf("address-->");
	for(int i=0;i<34;++i)printf("%c",addresscomp[i]);
	printf("\n");
	
	
	
	
}