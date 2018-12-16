#include<iostream>
#include<math.h>
#include<gmp.h>
#include<gmpxx.h>
#include <time.h>
#include "OAEP.h"

using namespace std;

const int BITS = 1024;
const int rounds = 64;

class RSA_Primes {

	mpz_t rsaP;
	mpz_t rsaQ;
	mpz_t n;
	mpz_t phi;
	mpz_t rsaE;
	mpz_t rsaD;
	mpz_t one;
public: mpz_t message;
public: mpz_t ciphertext;
public: mpz_t plaintext;

gmp_randstate_t rand;
unsigned long int seed;

public:
RSA_Primes() {
	seed = 1;
	mpz_init(rsaP);
	mpz_init(rsaQ);
	mpz_init(n);
	mpz_init(phi);
	mpz_init(rsaE);
	mpz_init(rsaD);
	mpz_init(message);
	mpz_init(ciphertext);
	mpz_init(plaintext);
	mpz_init(one);
	mpz_set_str(one, "1", 10);
	gmp_randinit_default (rand);
	gmp_randseed_ui(rand, seed);
}


// Miller-Rabin Primality Testing to find whether
//a randomly chosen odd number is a prime number or not
bool millerRabin_isPrimeCheck(mpz_t value) {

	if (mpz_even_p(value) == 1)
		return true;

	mpz_t tempValue;
	mpz_init(tempValue);
	mpz_sub_ui(tempValue, value, (unsigned int)1);

	mpz_t tempStore;
	mpz_init(tempStore);
	mpz_set(tempStore,tempValue);

	unsigned int a = 0;

	// Finding out the value for r which is (value / 2^d)
	while (true) {
		if (mpz_even_p(tempValue) == 0) {
			break;
		}
		a++;
		mpz_cdiv_q_ui(tempValue, tempValue, (unsigned int)2);
	}

	// Doing the check for 64 rounds
	for (size_t i=0; i<rounds; i++) {
		if (millerTest(tempValue,tempStore,value,a) == false)
			return false;
	}
	return true;
};

private: bool millerTest(mpz_t m, mpz_t tempStore, mpz_t value, unsigned int a) {

	mpz_t pickRandA;
	mpz_init(pickRandA);

	mpz_t storeX;
	mpz_init(storeX);

	// Picking up a random value between 0 and value-2
	mpz_urandomm(pickRandA, rand, tempStore);

	// Computing pickRandA ^ m mod given value
	mpz_powm(storeX, pickRandA, m, value);

	// Check whether the it is equal to 0 or (value-1)
	if (mpz_cmp_ui(value, (unsigned int )1) == 0 || mpz_cmp(value, tempStore) == 0)
	{
		return true;
	}

	for (size_t j=0; j<a-1; j++) {
		mpz_powm_ui(storeX, storeX, (unsigned long int)2, value);
		if (mpz_cmp_ui(storeX, (unsigned int )1) == 0) {
			// Not a prime, hence return false
			return false;
		}
		if (mpz_cmp(storeX, tempStore) == 0)
			return true;
	}
	return false;
};


public: void generateLargePrimeNumbers() {

	bool isPrimeFlag = false;

	// get a random integer which has bits of length BITS using mpz_urandomb method
	mpz_urandomb(rsaP,rand,BITS);
	isPrimeFlag = millerRabin_isPrimeCheck(rsaP);
	while(!isPrimeFlag)
	{
		mpz_nextprime(rsaP,rsaP);
		isPrimeFlag = millerRabin_isPrimeCheck(rsaP);
	}

	isPrimeFlag = false;
	// get a random integer which has bits of length BITS using mpz_urandomb method
	mpz_urandomb(rsaQ,rand,BITS);
	isPrimeFlag = millerRabin_isPrimeCheck(rsaQ);
	while(!isPrimeFlag)
	{
		mpz_nextprime(rsaQ,rsaQ);
		isPrimeFlag = millerRabin_isPrimeCheck(rsaQ);
	}

	// Calculate RSA modulus n and phi values
	mpz_mul(n,rsaP,rsaQ);
	mpz_t tempP;
	mpz_t tempQ;

	mpz_init(tempP);
	mpz_init(tempQ);

	mpz_sub(tempP,rsaP,one);
	mpz_sub(tempQ,rsaQ,one);

	mpz_mul(phi,tempP,tempQ);

	gmp_printf("chosen rsaP value: %Zd\n", rsaP);
	cout << "\n";
	gmp_printf("chosen rsaQ value: %Zd\n", rsaQ);
	cout << "\n";
	gmp_printf("RSA modulus n value: %Zd\n", n);

	cout << "\n";
	gmp_printf("RSA Phi value: %Zd\n", phi);
	cout << "\n";

}

public: void calculatePublicPrivateKeys() {
	//		unsigned long int coPrime = 65537;
	mpz_t gcdValue;
	mpz_init(gcdValue);

	mpz_t coPrime;
	mpz_init(coPrime);

	mpz_urandomb(coPrime, rand, BITS);

	while(true)
	{
		mpz_gcd(gcdValue,phi,coPrime);
		if(mpz_cmp_ui(gcdValue,(unsigned long int)1)==0)
			break;
		mpz_nextprime(coPrime, coPrime);
	}

	mpz_set(rsaE, coPrime);
	mpz_invert(rsaD, rsaE, phi);

	gmp_printf("chosen E value: %Zd\n", rsaE);
	cout << "\n";
	gmp_printf("chosen D value: %Zd\n", rsaD);
	cout << "\n";
}

void encryptMessage() {
	mpz_powm(ciphertext, message, rsaE, n);
	cout << "\n\nCipher Text: " <<ciphertext<<endl;
}

void decryptMessage() {
	mpz_powm(plaintext, ciphertext, rsaD, n);
	cout<< "\nDecrypted Text:"<<plaintext<<endl;
}

~RSA_Primes() {
	mpz_clear(rsaP);
	mpz_clear(rsaQ);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(rsaE);
	mpz_clear(rsaD);
	mpz_clear(message);
	mpz_clear(ciphertext);
}

};


int main() {

	RSA_Primes * rsa = new RSA_Primes;
	OAEP * oaep = new OAEP;

	// Generate 2 large prime numbers
	rsa->generateLargePrimeNumbers();

	// Calculating public and private keys using modulus n and phi
	rsa->calculatePublicPrivateKeys();

	char messageLabel[1000];
	cout<<"enter the message label :"<<"\n";
	cin>>messageLabel;

	cout<<"enter the message :"<<"\n";
	char message[1000];
	cin>>message;

	mpz_t encodedIntMessage;
	mpz_init(encodedIntMessage);

	// encoding the given message using OAEP scheme
	unsigned char * encodedOctetRep = oaep->getEncodedMessage(message, messageLabel);

	// Getting the integer representation of the encode message
	oaep->os2ip(encodedOctetRep, encodedIntMessage);
	cout << "Encoded Message in Integer Representation :"<<endl;
	cout<< encodedIntMessage;
	mpz_set(rsa -> message,encodedIntMessage);

	// encrypting the encoded message using the public key rsaE and modulus N
	rsa -> encryptMessage();

	// decrypting the cipher text
	rsa -> decryptMessage();

	// Getting the octet representation of the decrypted ciphter text to decode using OAEP scheme
	unsigned char * octetRep = oaep->i2osp(rsa->plaintext, modulus_n);

	// decoding the decrpted cipher text using OAEP scheme
	unsigned char * decodeMes =  oaep->getDecodedMessage(octetRep, messageLabel);

	// as per SEI coding standards MEM50-CPP
	delete rsa;
	delete oaep;

	// as per the SEI coding standards MEM31-C
	free (octetRep);
	free (decodeMes);
	free (encodedOctetRep);
	return 0;
}

