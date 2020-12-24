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
	
void unsigned_txn_to_byte_array(unsigned_txn utx,int ind,uint8_t *ubyte){
	int index=0;
	memcpy(&ubyte[index],utx.network_version,4);
	index+=4;
	memcpy(&ubyte[index],utx.input_count,1);
	index+=1;
	for(int i=0;i<(int)utx.input_count[0];++i){
		memcpy(&ubyte[index],utx.input[i].previous_txn_hash,32);
		index+=32;
		memcpy(&ubyte[index],utx.input[i].previous_output_index,4);
		index+=4;
		if(i==ind){
			memcpy(&ubyte[index],utx.input[i].script_length,1);
			index+=1;
			memcpy(&ubyte[index],utx.input[i].script_public_key,25);
			index+=25;
		}else{
			
			ubyte[index]=0x00;
			index+=1;
			
		}
		memcpy(&ubyte[index],utx.input[i].sequence,4);
		index+=4;
	}
	memcpy(&ubyte[index],utx.output_count,1);
	index+=1;
	
	for(int i=0;i<(int)utx.output_count[0];++i){
		memcpy(&ubyte[index],utx.output[i].value,8);
		index+=8;
		memcpy(&ubyte[index],utx.output[i].script_length,1);
		index+=1;
		memcpy(&ubyte[index],utx.output[i].script_public_key,25);
		index+=25;
	}
	memcpy(&ubyte[index],utx.locktime,4);
	index+=4;
	memcpy(&ubyte[index],utx.sighash,4);
	index+=4;
}
void byte_array_to_unsigned_txn(uint8_t* btc_unsigned_txn_byte_array, unsigned_txn* unsigned_txn_ptr)
{

    uint32_t offset = 0U, len = 0U;

    len = sizeof(unsigned_txn_ptr->network_version);
    memcpy(unsigned_txn_ptr->network_version, (btc_unsigned_txn_byte_array + offset), len);
    offset += len;

    len = sizeof(unsigned_txn_ptr->input_count);
    memcpy(unsigned_txn_ptr->input_count, (btc_unsigned_txn_byte_array + offset), len);
    offset += len;

    len = (*unsigned_txn_ptr->input_count) * sizeof(unsigned_txn_input);
    unsigned_txn_ptr->input = (unsigned_txn_input*)malloc(len);

    uint8_t inputIndex = 0U;
    for (; inputIndex < *unsigned_txn_ptr->input_count; inputIndex++) {
        len = sizeof(unsigned_txn_ptr->input[inputIndex].previous_txn_hash);
        memcpy(unsigned_txn_ptr->input[inputIndex].previous_txn_hash, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->input[inputIndex].previous_output_index);
        memcpy(unsigned_txn_ptr->input[inputIndex].previous_output_index, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->input[inputIndex].script_length);
        memcpy(unsigned_txn_ptr->input[inputIndex].script_length, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->input[inputIndex].script_public_key);
        memcpy(unsigned_txn_ptr->input[inputIndex].script_public_key, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->input[inputIndex].sequence);
        memcpy(unsigned_txn_ptr->input[inputIndex].sequence, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;
    }

    len = sizeof(unsigned_txn_ptr->output_count);
    memcpy(unsigned_txn_ptr->output_count, (btc_unsigned_txn_byte_array + offset), len);
    offset += len;

    len = (*unsigned_txn_ptr->output_count) * sizeof(txn_output);
    unsigned_txn_ptr->output = (txn_output*)malloc(len);

    uint8_t outputIndex = 0U;
    for (; outputIndex < *unsigned_txn_ptr->output_count; outputIndex++) {
        len = sizeof(unsigned_txn_ptr->output[outputIndex].value);
        memcpy(unsigned_txn_ptr->output[outputIndex].value, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->output[outputIndex].script_length);
        memcpy(unsigned_txn_ptr->output[outputIndex].script_length, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;

        len = sizeof(unsigned_txn_ptr->output[outputIndex].script_public_key);
        memcpy(unsigned_txn_ptr->output[outputIndex].script_public_key, (btc_unsigned_txn_byte_array + offset), len);
        offset += len;
    }

    len = sizeof(unsigned_txn_ptr->locktime);
    memcpy(unsigned_txn_ptr->locktime, (btc_unsigned_txn_byte_array + offset), len);
    offset += len;

    len = sizeof(unsigned_txn_ptr->sighash);
    memcpy(unsigned_txn_ptr->sighash, (btc_unsigned_txn_byte_array + offset), len);
    offset += len;
}

	
int main(void) 
{
	
	uint8_t *byte=fromhex("0200000002af1f84ac5a0d83b106c8be402ec4d994ce59277ff57418e4cf385d3cd1f90264000000001976a91463047aebd3da248f2e7b63e0864d3c2f07922fd788acffffffff4a308a7c0d58d744cf707fb4ab873fffaa7de6b9b00a9605696371730fd14044010000001976a91463047aebd3da248f2e7b63e0864d3c2f07922fd788acffffffff0140420f00000000001976a9146e26f46c5820e99bf22b79ba26a81810dbc5f37588ac00000000");
	const char *mnemonic="library movie around trust valve key time resemble step because absent cement purity transfer arctic assault never canvas awake leave exchange alert flee onion";
	
	 char *metadata="8000002c80000001800000000200000000000000000000000000000000000000000000000000010000000100000000";
	unsigned_txn utx;
	signed_txn sign_txn;
	const ecdsa_curve *curve=&secp256k1;
	byte_array_to_unsigned_txn(byte,&utx);
	
	char *passphase ="";
	HDNode master;
	uint8_t bip39seed[512/8],publickey[32];
	mnemonic_to_seed(mnemonic,passphase,bip39seed,0);
	
	//m
	hdnode_from_seed(bip39seed,64,SECP256K1_NAME,&master);
	hdnode_fill_public_key(&master);
	
	//m/44'
	hdnode_private_ckd_prime(&master,44);
	hdnode_fill_public_key(&master);
	
	//m/44'/1'
	hdnode_private_ckd_prime(&master,1);
	hdnode_fill_public_key(&master);
	
	//m/44'/1'/0'
	hdnode_private_ckd_prime(&master,0);
	hdnode_fill_public_key(&master);

	//m/44'/1'/0'/0
	hdnode_private_ckd(&master,0);
	hdnode_fill_public_key(&master);
	
	int y=(int)utx.input_count[0],z=(int)utx.output_count[0],metaindex=34;
  	uint8_t ubyte[14+41*y+34*z+25],hash[SHA256_DIGEST_LENGTH],dhash[SHA256_DIGEST_LENGTH];
  	uint8_t scriptpb[(int)y][25];
  	
  	for(int i=0;i<(int)y;++i){
  		memcpy(&scriptpb[i],utx.input[i].script_public_key,25);
	}

	memcpy(&sign_txn.network_version,utx.network_version,4);
	memcpy(&sign_txn.input_count,utx.input_count,1);

	uint32_t  len = 0U;
    len = (y) * (sizeof(signed_txn_input));
    sign_txn.input = (signed_txn_input*)malloc(len);

	for(int i=0;i<(int)y;i++){
		memcpy(&sign_txn.input[i].previous_txn_hash,utx.input[i].previous_txn_hash,32);
		memcpy(&sign_txn.input[i].previous_output_index,utx.input[i].previous_output_index,4);
		sign_txn.input[0].previous_txn_hash[0]=utx.input[0].previous_txn_hash[0];
		memcpy(&sign_txn.input[i].sequence,utx.input[i].sequence,4);
	}
	memcpy(&sign_txn.output_count,utx.output_count,1);
	len = (z) * (sizeof(txn_output));
    sign_txn.output = (txn_output*)malloc(len);
	for(int i=0;i<(int)z;i++){
		memcpy(&sign_txn.output[i].value,utx.output[i].value,8);
		memcpy(&sign_txn.output[i].script_length,utx.output[i].script_length,1);
		memcpy(&sign_txn.output[i].script_length,utx.output[i].script_public_key,25);
	}
	memcpy(&sign_txn.locktime,utx.locktime,4);
	
	for(int i=0;i<y;++i){
		unsigned_txn_to_byte_array(utx,i,ubyte);
		
		sha256_Raw(&ubyte,sizeof(ubyte),hash);	
		sha256_Raw(&hash,sizeof(hash),dhash);
		
		char hexa[8];
		for(int j=0;j<8;++j,metaindex++)hexa[j]=metadata[metaindex];
		metaindex+=8;
		int num=(int)strtol(hexa,NULL,16);
		
		HDNode add=master;
		hdnode_private_ckd(&add,num);
		hdnode_fill_public_key(&add);

		uint8_t sig[64],der[72];
		int x=ecdsa_sign_digest(curve,add.private_key,dhash,sig,0,0);
		x=ecdsa_sig_to_der(sig,&der);
		
		sign_txn.input[i].script_length[0]=(uint8_t)x+36;
		sign_txn.input[i].script_sig[0]=(uint8_t)x+1;
		sign_txn.input[i].script_sig[x+1]=(uint8_t)1;
		sign_txn.input[i].script_sig[x+2]=(uint8_t)33;
		memcpy(&sign_txn.input[i].script_sig[1],der,x);
		memcpy(&sign_txn.input[i].script_sig[x+3],add.public_key,33);

		printf("\n\ninput ->%d\n",i);
		printf("\npublic key-->");
		for(int j=0;j<33;++j){printf("%02X",add.public_key[j]);}
		printf("\n");
		printf("\n");
		printf("private key-->");
		for(int j=0;j<33;++j){printf("%02X",add.private_key[j]);}
		printf("\n");
		printf("\n");
		printf("script_sig-->");
		for(int j=0;j<x+35;j++){
			printf("%02X",sign_txn.input[i].script_sig[j]);
		}
		
		
	}
	return 0;
	
	
	
	
}