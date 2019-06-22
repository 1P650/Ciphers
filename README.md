# Ciphers

Just implementation of different ciphers/hash functions/others.
#### WARNING: Some of them might be not correctly implemented.

## Contains 
### Ciphers
#### Block Ciphers
* Aardvark
* GOST28147-89 (ГОСТ28147-89) (ECB mode,CFB mode, CTR mode, MAC (Imitovstavka)) 
* TEA (Tiny Encryption Algorithm) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* IDEA (International Data Encryption Algorithm) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* CAST-128 (CAST5) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* CAST-256 (CAST6) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
***
### Hash Functions
* SHA1
* SHA2: SHA224, SHA256, SHA384, SHA512, SHA512/256, SHA512/224
***
### Pseudorandom number generators
* Simple linear congruential PRNG
* ISAAC CSPRNG (not correctly implemented but still)
***

### Applied utils
* Cascade encryption (CipherCascade)
***

### Utils
* BitUtil (bit rotation, type conversion, hex&binary print,more)
* AlgorithmUtil (index of element, reverse array, reverse matrix)
* MathUtil (modulo operations, more will be soon)


