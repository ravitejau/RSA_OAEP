#include <iostream>
#include <stdio.h>
#include "gmp.h"
#include <openssl/sha.h>
#include <string.h>
#include <cstdlib>
#include <math.h>

using namespace std;

const int modulus_n = 256;
const int hlen = 32;

class OAEP
{

	int messageLen;
	int messageLabelLen;
	char lHash[hlen+1];
	int dbLen = modulus_n - hlen - 1;

public :

	void os2ip(unsigned char octetString[], mpz_t result);
	unsigned char * i2osp(mpz_t integerValue, int xLen);
	unsigned char * getEncodedMessage(char message[], char messageLabel[]);
	unsigned char * getDecodedMessage(unsigned char encodedMessage[], char messageLabel[]);
private:
	void maskGenerationFunction(int ceilValue, int len, unsigned char input[], unsigned char output[]);
};

// Converting Octet Representation to Integer Representation using OS2IP technique

void OAEP::os2ip(unsigned char octetString[], mpz_t result) {
	int len = strlen((char *)octetString);
	mpz_t base;
	mpz_init(base);
	mpz_set_ui(base,(unsigned int)256);

	for (int index=0; index<len; index++) {
		mpz_t mulValue;
		mpz_init(mulValue);

		mpz_t value;
		mpz_init(value);
		mpz_pow_ui(value,base,(unsigned long int)index);

		mpz_mul_ui(mulValue, value, (unsigned long int)octetString[index]);
		mpz_add(result, result, mulValue);
	}

}

// Converting Integer Representation to Octet Representation using OS2IP technique
unsigned char * OAEP::i2osp(mpz_t integerValue, int xLen) {

	cout << "\n";
	unsigned char * result = (unsigned char *) malloc(2*xLen + 1);
	mpz_t modValue;
	mpz_init(modValue);
	mpz_set_ui(modValue, 256);

	for (int inc=0; inc<2*xLen; inc++) {

		mpz_t remainder;
		mpz_init(remainder);
		mpz_powm_ui(remainder, integerValue, (unsigned int )1, modValue);
		char * block = mpz_get_str(NULL , 10, remainder);
		int blocklen = strlen((char *)block)-1;
		std::string str;
		str.append(block);
		result[inc] = std::atoi(str.c_str());
		mpz_div_ui(integerValue, integerValue, (unsigned int)256);
	}
	result[2*xLen] = '\0';
	return result;
}

//Mask Generation Function to get the required number of output bits

void OAEP::maskGenerationFunction(int ceilValue, int len, unsigned char input[], unsigned char output[])
{
	for (int counter=0; counter<=ceilValue; counter++)			//generating hash a particular number of times and appending the hash values
	{
		unsigned char * obuf;
		obuf = (unsigned char *)malloc(20+1);
		unsigned char bytes1[4];
		bytes1[0] = (counter >> 24) & 0xFF;
		bytes1[1] = (counter >> 16) & 0xFF;
		bytes1[2] = (counter >> 8) & 0xFF;
		bytes1[3] = counter | 0x00;
		unsigned char hashInput1[len+5];
		for (int i=0; i<len; i++)
		{
			hashInput1[i] = input[i];
		}
		for (int i=0; i<4; i++)
		{
			hashInput1[len+i] = bytes1[i];
		}
		// as per SEI coding standards STR32-C
		hashInput1[len+4] = '\0';

		SHA1((unsigned char *)hashInput1,strlen((char*)hashInput1),(unsigned char *)obuf);
		for (int i=0; i<20; i++)
		{
			int index = counter*20 + i;
			output[index] = obuf[i];
		}
		free (obuf);
	}
}

// Encoding the given input message using the specifoed algorithm

unsigned char * OAEP::getEncodedMessage(char message[], char messageLabel[])

{

	int checkLen = modulus_n-(2*hlen)-2;
	messageLen = strlen(message);
	messageLabelLen = strlen(messageLabel);
	int psLen = checkLen - messageLen;
	unsigned char ps[psLen];

	// validating message length
	if (messageLen > checkLen) {
		cout << "message too long";
		return NULL;
	}

	// label length has to be validated
	// hashing the message label to get lhash
	SHA256((unsigned char *)messageLabel,strlen((char*)messageLabel),(unsigned char *)lHash);
	cout<<"\n";

	// framing PS(padding string) containing psLen 0's
	for(int index=0;index<psLen;index++)
	{
		ps[index]='0';
	}


	// framing DB using lhash, PS and message
	unsigned char *db;
	db = (unsigned char *) malloc(dbLen+1);
	for(int i=0;i<hlen;i++)
	{
		db[i] = lHash[i];

	}
	for (int j=0; j<psLen; j++) {
		db[j+hlen] = ps[j];

	}

	db[hlen+psLen] = '1';

	for (int k=0; k<messageLen; k++) {
		db[hlen+psLen+1+k] = message[k];


	}
	// according the SEI coding standards STR31-C
	db[dbLen] = '\0';

	cout << "\n";

	// forming a random seed of length hlen
	unsigned char seed[hlen+1];
	srand(time(NULL));

	for(int i=0;i<hlen;i++)
	{
		seed[i] = (char)rand()%128;
	}
	// according the SEI coding standards STR31-C
	seed[hlen] = '\0';

	//mask generation function
	cout <<"\n";
	int ceilValue = ceil((double)dbLen/20)-1;
	unsigned char extendedSeed[20*(ceilValue+1)];
	maskGenerationFunction(ceilValue, hlen, seed, extendedSeed);



	// Performing XOR Operation on DB and output of MGF(seed)
	unsigned char maskedDB[dbLen+1];
	for(int i = 0; i < dbLen; i++)
	{
		maskedDB[i] = extendedSeed[i] ^ db[i];
	}
	maskedDB[dbLen] = '\0';

	//Mask Generation Function 2
	cout<<"\n";

	int ceilValue1 = int(ceil((double)hlen/20))-1;
	unsigned char extendedSeed1[20*(ceilValue1+1)];
	maskGenerationFunction(ceilValue1, dbLen, maskedDB, extendedSeed1);


	// Performing XOR Operation on DB and output of MGF(seed)
	unsigned char masked_Seed[hlen+1];
	for(int i = 0; i < hlen; i++)
	{
		masked_Seed[i] = extendedSeed1[i] ^ seed[i];

	}
	masked_Seed[hlen] = '\0';
	cout << "\n";


	unsigned char * encoded_message;
	encoded_message = (unsigned char *)malloc(modulus_n+1);
	encoded_message[0]='0';

	int cnt=1;

	for(int i=0;i<hlen;i++)
	{
		encoded_message[cnt]=masked_Seed[i];
		cnt++;
	}

	for(int i=0;i<dbLen;i++)
	{
		encoded_message[cnt]=maskedDB[i];
		cnt++;
	}

	// According to SEI coding standards STR31-C
	encoded_message[modulus_n] = '\0';

	// as per SEI coding standards MEM31-C
	free (db);
	return encoded_message;
}

//Decoding the message obtained after decryption

unsigned char * OAEP::getDecodedMessage(unsigned char encodedMessage[], char messageLabel[])
{

	unsigned char * seed;
	unsigned char * db;
	unsigned char * maskedSeed;
	unsigned char * maskedDB;
	seed = (unsigned char *)malloc(hlen);
	db = (unsigned char *)malloc(dbLen);
	maskedSeed = (unsigned char *)malloc(hlen);
	maskedDB = (unsigned char *)malloc(dbLen);

	for (int index=0; index<hlen; index++)
		maskedSeed[index] = encodedMessage[index+1];
	for (int index=0; index<dbLen; index++)
		maskedDB[index] = encodedMessage[index+hlen+1];

	// XORing masked seed with MGF(maskedDB, hlen) to get seed
	int ceilValue = int(ceil((double)hlen/20))-1;
	unsigned char extendedMask[20*(ceilValue+1)];
	maskGenerationFunction(ceilValue, dbLen, maskedDB, extendedMask);

	for(int i = 0; i < hlen; i++)
	{
		seed[i] = extendedMask[i] ^ maskedSeed[i];

	}
	cout << "\n";

	int ceilV = ceil((double)dbLen/20)-1;
	unsigned char * extendedSeed;
	extendedSeed = (unsigned char *)malloc(20*(ceilV+1));

	//Calculating extended seed which is the output of Mask Generation Function

	maskGenerationFunction(ceilV, hlen, seed, extendedSeed);



/*
	for (int index=0; index<dbLen; index++)
		cout << maskedDB[index];*/
	cout << "\n";

	// Xoring extended seed with Masked DB
	for(int index = 0; index < dbLen; index++)
	{
		db[index] = extendedSeed[index] ^ maskedDB[index];

	}
	cout << "\n";

	unsigned char * decodedMessage;
	int lengthMess = 0;
	bool flag = false;

	cout << "Message obtained after decoding : \n";
	for (int index=hlen; index<dbLen; index++) 					//Taking the message from the encoded message

	{
		if (db[index] == '0' || db[index] == '1')
			continue;
		lengthMess = index;
		break;
	}

	decodedMessage = (unsigned char *)malloc(dbLen-lengthMess);
	for (int index=lengthMess; index<dbLen; index++) {
		decodedMessage[index-lengthMess] = db[index];
		cout << db[index];
	}

	cout << "\n";

	// as per SEI coding standards MEM31-C
	free (seed);
	free (db);
	free (maskedSeed);
	free (maskedDB);
	return decodedMessage;
}
