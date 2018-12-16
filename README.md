## Implementation OF RSA OAEP Algorithm Securely

Plain RSA is susceptible to certain attacks like Adaptive Chosen Ciphertext Attack and Chosen Plaintext Attacks. Chosen Plaintext attacks occur if the encryption algorithm is deterministic in nature. The RSA OAEP algorithm from the RFC 8017(PKCS v2.2) which encodes the given plain text by introducing an element of randomness called the seed and thus making it non-deterministic.

## Generation of large prime numbers p and q.

The first task involved in this project is the generation of large prime numbers p and q. we have used GMP library to store large integers. We have initially generated large random numbers using “mpz_urandom” function which takes as input the number of bits of the random number to be generated. We then stored the large random numbers generated in the mpz_t data type variables. We then do a primality test by calling the Miller Rabin Primality Test function by passing the random number generated above as a parameter to the method. The Miller Rabin Primality Test checks whether the large random number generated is probable prime or composite. If it is composite, we generate another random number and do the same process of checking the primality of the number. We continue this process until we obtain a large prime number. We implemented the Miller Rabin Primality Test using the standard FIPS 186-3.
