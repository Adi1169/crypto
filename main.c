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
#define VERSION_PRIVATE 0x0488ade4

#define FROMHEX_MAXLEN 512
typedef struct
{
    uint8_t previous_txn_hash[32];
    uint8_t previous_output_index[4];
    uint8_t script_length[1];
    uint8_t script_public_key[25];
    uint8_t sequence[4];
} unsigned_txn_input;

#pragma pack(1)
typedef struct
{
    uint8_t previous_txn_hash[32];
    uint8_t previous_output_index[4];
    uint8_t script_length[1];
    uint8_t script_sig[128];
    uint8_t sequence[4];
} signed_txn_input;

#pragma pack(1)
typedef struct
{
    uint8_t value[8];
    uint8_t script_length[1];
    uint8_t script_public_key[25];
} txn_output;

#pragma pack(1)
typedef struct
{
    uint8_t network_version[4];
    uint8_t input_count[1];
    unsigned_txn_input* input;
    uint8_t output_count[1];
    txn_output* output;
    uint8_t locktime[4];
    uint8_t sighash[4];

} unsigned_txn;

#pragma pack(1)
typedef struct
{
    uint8_t network_version[4];
    uint8_t input_count[1];
    signed_txn_input* input;
    uint8_t output_count[1];
    txn_output* output;
    uint8_t locktime[4];
} signed_txn;

#pragma pack(1)
typedef struct
{
    uint8_t chain_index[4];
    uint8_t address_index[4];
} address_type;

#pragma pack(1)
typedef struct
{
    uint8_t wallet_index[1];
    uint8_t purpose_index[4];
    uint8_t coin_index[4];
    uint8_t account_index[4];

    uint8_t input_count[1];
    address_type* input;

    uint8_t output_count[1];
    address_type* output;

    uint8_t change_count[1];
    address_type* change;

    uint8_t transactionFees[4];

    uint8_t decimal[1];

    char token_name[8];

} txn_metadata;

const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}
int check(uint8_t * txn,int32_t index){
	int size=(int)txn[index];
	bignum256 bg;
	if(size<=(int)0x7f && size>=(int)0x00){
		return 0;
		}
	else if(size<=0xb7 && size>=0x80){
		return ((int)txn[index]-0x80);
	}
	else if(size<=0xbf && size>=0xb8){
		uint8_t a[(int)size-0xb8];
		index++;
		memcpy(&a,txn[index],(int)size-0xb8);
		int32_t temp=read_le(&a);
		return temp+(int)size-0xb8;
		
	}
	else if(size<=0xf7 && size>=0xc0){
		return ((int)txn[index]-0xc0);
		}
	else if(size<=0xff && size>=0xf8){
		uint8_t a[(int)size-0xf8];
		index++;
		memcpy(&a,txn[index],(int)size-0xf8);
		int32_t temp=read_le(&a);
		return temp+(int)size-0xf8;
	}
}
		
void eth_code(uint8_t *txn){
	
	uint64_t val;
	
	int index=0;

	int x;
	
	
	int size=(int)txn[index];
	
	if(size<=0x7f && size>=0x00){
		index+=0;
	}
	else if(size<=0xb7 && size>=0x80){
		index+=0;
	}
	else if(size<=0xbf && size>=0xb8){
		index+= (int)size-0xb7;
		
	}
	else if(size<=0xf7 && size>=0xc0){
		index+= 0;
	}
	else if(size<=0xff && size>=0xf8){
		index+= (int)size-0xf7;
	}
	index++;

	//nonce:
	x=check(txn,index);
	index+=(x+1);
	
	//gas price:
	x=check(txn,index);
	index+=(x+1);
	
	//gas limit:
	x=check(txn,index);
	index+=(x+1);
	
	//recepient
	x=check(txn,index);
	uint8_t address[x-1],token[x-1];
	printf("\n\n adress: \n\n");
	memcpy(&address,&txn[index+1],x-1);
	memcpy(&token,&txn[index+1],x-1);
	for(int i=0;i<x-1;++i){
		printf("%02x",address[i]);
	}
	index+=x+1;
	
	//value
	x=check(txn,index); 
	uint8_t a[4]={' '};
	
	index++;
	for(int i=4-x;i<4;i++){
		a[i]=txn[index++];
	}
	for(int i=0;i<4-x;i++){
		a[i]=(uint8_t)0;
	}

	uint64_t value=read_be(a);
	index+=x+1;

	if(value==0){
		index+=8;
		int ans=index;
		printf("\n\nreceipent adress:\n\n");
		while(txn[ans]==(uint8_t)0 && ans<index+32)++ans;
		memcpy(&address,&txn[ans],index+29-ans);
		for(int i=0;i<index+29-ans;++i){
			printf("%02x",address[i]);
		}

		index+=32;
		ans=index;
		printf("\n\nerc value:\n\n");
		while(txn[ans]==(uint8_t)0 && ans<index+32)++ans;
		memcpy(&address,&txn[ans],index+29-ans);
		for(int i=0;i<index+29-ans;++i){
			printf("%02x",address[i]);
		}
		
		
	}
	else{
		printf("\n\neth value %d",value);
	} 
}
	
	
	
	
		
	
	
	
	
int main(void) 
{
	
	uint8_t *txn=fromhex("f86906850c92a69c0082520894eef5e2d8255e973d587217f9509b416b41ca587080b844a9059cbb0000000000000000000000006523ab57d3d1daced28dda50e2c9a5855388df8200000000000000000000000000000000000000000000d3c21bcecceda1000000038080x");
	eth_code(txn);
	uint8_t hash[32];
	const ecdsa_curve *curve=&secp256k1;
	const char *mnemonic="garment opinion monitor gold never catalog  pond sunset spell penalty wrist favorite dinner powder meat sugar company west forest witness kind copper grief gasp";
	
	keccak_256(txn,strlen(txn),&hash);
	char *passphase ="";
	HDNode master;
	uint8_t bip39seed[512/8],publickey[32];
	mnemonic_to_seed(mnemonic,passphase,bip39seed,0);
	
	//m
	hdnode_from_seed(bip39seed,64,SECP256K1_NAME,&master);
	
	//m/44'
	hdnode_private_ckd_prime(&master,44);
	
	//m/44'/60'
	hdnode_private_ckd_prime(&master,60);
	
	
	//m/44'/1'/0'
	hdnode_private_ckd_prime(&master,0);

	//m/44'/1'/0'/0
	hdnode_private_ckd(&master,0);
	
	//m/44'/1'/0'/0/0
	hdnode_private_ckd(&master,0);
	hdnode_fill_public_key(&master);
	
		
	uint8_t sig[64];
	ecdsa_sign_digest(curve,master.private_key,hash,sig,0,0);
	
	
	int p=(int)sig[63];
	int chainId=3;
	uint8_t v=(uint8_t)(2 * chainId + 35);
	if(p%2==1)++v;
	
	
	
	
		
	
	
	
	
}